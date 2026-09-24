//! The bridge as a process: the binary started on a configuration file, and
//! plain HTTP/1.1 requests to it over TCP.

use std::{
    io::{
        BufRead,
        BufReader,
        Read,
        Write,
    },
    net::{
        SocketAddr,
        TcpStream,
    },
    process::{
        Child,
        Command,
        Stdio,
    },
    sync::{
        mpsc::{
            self,
            RecvTimeoutError,
        },
        Arc,
        Mutex,
    },
    time::Duration,
};

use super::ScratchFile;

/// How long a started bridge has to say where it listens.
const STARTUP_BUDGET: Duration = Duration::from_secs(30);

/// The binary's command on an environment carrying nothing but the loopback
/// port to bind and the log filter, and no configuration file.
fn unconfigured() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_libid-bridge-rs"));
    command
        .env_clear()
        // The coverage profile path, when the test runs under one.
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        // Where a test's bridge listens is not a key of its file.
        .env("HOST", "127.0.0.1")
        .env("PORT", "0")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The same, with `config` written to a file it is pointed at. The file is
/// removed when the returned handle is dropped, so it outlives the run.
fn command(config: &str) -> (Command, ScratchFile) {
    let file = ScratchFile::holding(config);
    let mut command = unconfigured();
    command.env("LIBID_CONFIG", file.path());
    (command, file)
}

/// What the binary printed and how it exited, for a configuration it does
/// not start on.
pub fn attempt(config: &str) -> std::process::Output {
    let (command, _file) = command(config);
    ran(command)
}

/// The same for a run that names no configuration file.
pub fn attempt_unconfigured() -> std::process::Output {
    ran(unconfigured())
}

fn ran(mut command: Command) -> std::process::Output {
    command
        .spawn()
        .expect("the binary starts")
        .wait_with_output()
        .expect("the binary exits")
}

/// A running bridge.
pub struct Bridge {
    child: Child,
    /// The configuration it was started on, removed when it stops.
    _config: ScratchFile,
    /// Where it listens.
    pub address: SocketAddr,
    /// Everything it has printed after the address, forwarded to the test
    /// output as it arrives.
    printed: Arc<Mutex<String>>,
    forwarding: Option<std::thread::JoinHandle<()>>,
}

impl Bridge {
    /// The binary on `config`, once it has said where it listens, within
    /// [`STARTUP_BUDGET`]; a bridge that says nothing by then is stopped.
    pub fn started(config: &str) -> Bridge {
        let (mut command, file) = command(config);
        let mut child = command.spawn().expect("the binary starts");
        let stdout = BufReader::new(child.stdout.take().expect("a piped stdout"));
        let printed = Arc::new(Mutex::new(String::new()));
        let sink = printed.clone();
        let (bound, address) = mpsc::channel::<String>();
        // Every line goes to the test output; the one naming the address goes
        // to `address`, and every line after it to `printed`.
        let forwarding = std::thread::spawn(move || {
            let mut bound = Some(bound);
            for line in stdout.lines().map_while(Result::ok) {
                eprintln!("{line}");
                match bound.take() {
                    Some(tx) => match line.split("listening on ").nth(1) {
                        Some(rest) => {
                            let _ = tx.send(rest.trim().to_owned());
                        }
                        None => bound = Some(tx),
                    },
                    None => {
                        let mut printed = sink.lock().unwrap();
                        printed.push_str(&line);
                        printed.push('\n');
                    }
                }
            }
        });
        let address = match address.recv_timeout(STARTUP_BUDGET) {
            Ok(address) => address.parse().expect("the address the binary printed"),
            Err(RecvTimeoutError::Disconnected) => panic!(
                "the binary exited before binding: {}",
                stderr_of(&mut child)
            ),
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the binary printed no address within {STARTUP_BUDGET:?}")
            }
        };
        Bridge {
            child,
            _config: file,
            address,
            printed,
            forwarding: Some(forwarding),
        }
    }

    /// `SIGINT`, then the exit status and everything printed after the
    /// address.
    pub fn interrupted(mut self) -> (std::process::ExitStatus, String) {
        let signalled = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(signalled.success());
        let exit = self.child.wait().expect("the binary exits");
        if let Some(forwarding) = self.forwarding.take() {
            let _ = forwarding.join();
        }
        let printed = self.printed.lock().unwrap().clone();
        (exit, printed)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut text);
    }
    text
}

/// One HTTP/1.1 response, read whole over a connection that closes after it.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    /// The reply of the bridge at `address` to one request.
    pub fn to(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\ncontent-length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);

        let mut socket = TcpStream::connect(address).expect("the bridge accepts");
        socket
            .write_all(request.as_bytes())
            .expect("the request is sent");
        let mut raw = Vec::new();
        socket.read_to_end(&mut raw).expect("the response is read");
        let raw = String::from_utf8_lossy(&raw);

        let (head, body) = raw
            .split_once("\r\n\r\n")
            .expect("a response head before the body");
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .expect("a status line");
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        Reply {
            status,
            headers,
            body: body.to_owned(),
        }
    }

    /// The first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

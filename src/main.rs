use argparse;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::thread;
use subprocess::{Popen, PopenConfig, Redirection};
use which;

const IAC: u8 = 255;

#[derive(FromPrimitive, ToPrimitive, PartialEq, Debug, Clone)]
enum IACCommand {
    SE = 240,
    NOP = 241,
    DM = 242,
    BRK = 243,
    IP = 244,
    AO = 245,
    AYT = 246,
    EC = 247,
    EL = 248,
    GA = 249,
    SB = 250,
    WILL = 251,
    WONT = 252,
    DO = 253,
    DONT = 254,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq, Debug, Clone, Hash, Eq, Copy)]
enum IACOption {
    BinaryTransmission = 0,
    Echo = 1,
    Reconnection = 2,
    SuppressGoAhead = 3,
    ApproxMessageSizeNegotiation = 4,
    Status = 5,
    TimingMark = 6,
    RemoteControlledTransAndEcho = 7,
    OutputLineWidth = 8,
    OutputPageSize = 9,
    OutputCarriageReturnDisposition = 10,
    OutputHorizontalTabStops = 11,
    OutputHorizontalTabDisposition = 12,
    OutputFormfeedDisposition = 13,
    OutputVerticalTabstops = 14,
    OutputVerticalTabDisposition = 15,
    OutputLinefeedDisposition = 16,
    ExtendedASCII = 17,
    Logout = 18,
    ByteMacro = 19,
    DataEntryTerminal = 20,
    SUPDUP = 21,
    SUPDUPOutput = 22,
    SendLocation = 23,
    TerminalType = 24,
    EndOfRecord = 25,
    TACACSUserIdentification = 26,
    OutputMarking = 27,
    TerminalLocationNumber = 28,
    Telnet3270Regime = 29,
    X3PAD = 30,
    NegotiateAboutWindowSize = 31,
    TerminalSpeed = 32,
    RemoteFlowControl = 33,
    Linemode = 34,
    XDisplayLocation = 35,
    EnvironmentOption = 36,
    AuthenticationOption = 37,
    EncryptionOption = 38,
    NewEnvironmentOption = 39,
    TN3270E = 40,
    XAUTH = 41,
    CHARSET = 42,
    TelnetRemoteSerialPort = 43,
    ComPortControlOption = 44,
    TelnetSuppressLocalEcho = 45,
    TelnetStartTLS = 46,
    KERMIT = 47,
    SENDURL = 48,
    ForwardX = 49,
    ExtendedOptionsList = 255,
}

#[derive(Debug)]
struct IAC {
    command: IACCommand,
    option: Option<IACOption>,
    extra: Option<Vec<u8>>,
}

fn iac_sb_lengths(option: Option<IACOption>) -> Option<usize> {
    match option {
        Some(IACOption::NegotiateAboutWindowSize) => Some(4),
        _ => None,
    }
}

impl IAC {
    fn new(command: IACCommand, option: Option<IACOption>, extra: Option<Vec<u8>>) -> IAC {
        IAC {
            command,
            option,
            extra,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![IAC];
        bytes.push(self.command.to_u8().unwrap());
        if let Some(option) = &self.option {
            bytes.push(option.to_u8().unwrap());
            if let Some(extra) = &self.extra {
                assert!(self.command == IACCommand::SB);
                let length = extra.len();
                match iac_sb_lengths(self.option.clone()) {
                    Some(expected) => {
                        if length != expected {
                            panic!("Invalid IAC SB length: {}", length);
                        }
                    }
                    None => {
                        println!("Warning: IAC SB length not checked: {}", length);
                    }
                }
                let mut esc_extra: Vec<u8> = Vec::new();
                for byte in extra {
                    if *byte == IAC {
                        esc_extra.push(IAC);
                    }
                    esc_extra.push(*byte);
                }
                bytes.append(&mut esc_extra);
                bytes.push(IAC);
                bytes.push(IACCommand::SE.to_u8().unwrap());
            }
        }
        bytes
    }

    fn send(&self, stream: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        let bytes = self.to_bytes();
        println!("Sent IAC: {:?}", self);
        stream.write_all(&bytes)
    }

    fn create_do(option: IACOption) -> IAC {
        IAC {
            command: IACCommand::DO,
            option: Some(option),
            extra: None,
        }
    }

    fn create_dont(option: IACOption) -> IAC {
        IAC {
            command: IACCommand::DONT,
            option: Some(option),
            extra: None,
        }
    }

    fn create_will(option: IACOption) -> IAC {
        IAC {
            command: IACCommand::WILL,
            option: Some(option),
            extra: None,
        }
    }

    fn create_wont(option: IACOption) -> IAC {
        IAC {
            command: IACCommand::WONT,
            option: Some(option),
            extra: None,
        }
    }

    fn send_do(option: IACOption, stream: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        IAC::create_do(option).send(stream)
    }

    fn send_dont(option: IACOption, stream: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        IAC::create_dont(option).send(stream)
    }

    fn send_will(option: IACOption, stream: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        IAC::create_will(option).send(stream)
    }

    fn send_wont(option: IACOption, stream: &mut dyn std::io::Write) -> Result<(), std::io::Error> {
        IAC::create_wont(option).send(stream)
    }

    fn create_naws(width: u16, height: u16) -> IAC {
        IAC {
            command: IACCommand::SB,
            option: Some(IACOption::NegotiateAboutWindowSize),
            extra: Some(vec![
                (width >> 8) as u8,
                (width & 0xFF) as u8,
                (height >> 8) as u8,
                (height & 0xFF) as u8,
            ]),
        }
    }

    fn get_naws(&self) -> (u16, u16) {
        assert!(self.command == IACCommand::SB);
        assert!(self.option.as_ref().unwrap().clone() == IACOption::NegotiateAboutWindowSize);
        let extra = self.extra.as_ref().unwrap();
        assert!(extra.len() == 4);
        let width = ((extra[0] as u16) << 8) | (extra[1] as u16);
        let height = ((extra[2] as u16) << 8) | (extra[3] as u16);
        (width, height)
    }

    fn get_term_type(&self) -> String {
        assert!(self.command == IACCommand::SB);
        assert!(self.option.as_ref().unwrap().clone() == IACOption::TerminalType);
        let extra = self.extra.as_ref().unwrap();
        assert!(extra.len() > 1);
        assert!(extra[0] == 0);
        let mut term_type = String::new();
        for byte in extra.iter().skip(1) {
            term_type.push(*byte as char);
        }
        term_type
    }
}

#[derive(Debug, PartialEq)]
enum IACParseStateEnum {
    FindIAC,
    FindCommand,
    FindOption,
}

#[derive(Debug)]
struct IACParser {
    state: IACParseStateEnum,
    subnegotiation: bool,
    command: Option<u8>,
    option: Option<u8>,
    extra: Vec<u8>,
}

impl IACParser {
    fn create() -> IACParser {
        IACParser {
            state: IACParseStateEnum::FindIAC,
            subnegotiation: false,
            command: None,
            option: None,
            extra: Vec::new(),
        }
    }

    fn reset(&mut self) -> () {
        self.state = IACParseStateEnum::FindIAC;
        self.subnegotiation = false;
        self.command = None;
        self.option = None;
        self.extra = Vec::new();
    }

    fn emit_iac(&self) -> Result<IAC, std::io::Error> {
        let command = IACCommand::from_u8(self.command.unwrap()).unwrap();
        let option = if self.option.is_some() {
            IACOption::from_u8(self.option.unwrap())
        } else {
            None
        };
        if self.option.is_some() {
            if option.is_none() {
                return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Unknown IAC option: {} on cmd {:?}",
                            self.option.unwrap(),
                            command
                        ),
                ));
            }
        }
        let iac = IAC {
            command,
            option,
            extra: if self.extra.len() > 0 {
                Some(self.extra.clone())
            } else {
                None
            },
        };
        Ok(iac)
    }

    fn parse_and_send<F>(
        &mut self,
        buffer: &[u8],
        stream: &mut dyn std::io::Write,
        mut fn_handle_iac: F,
    ) -> Result<(), std::io::Error>
        where
            F: FnMut(Result<&IAC, &std::io::Error>) -> (),
        {
            let mut i = 0;
            let mut o = 0;
            let mut out_buffer = [0; 1024];
            //println!("buffer: {:?}, {}", buffer, buffer.len());
            while i < buffer.len() {
                if self.state != IACParseStateEnum::FindIAC {
                    //println!("i: {}, o: {}, parser {:?}", i, o, self);
                }
                let byte = buffer[i];
                match self.state {
                    IACParseStateEnum::FindIAC => {
                        if byte == IAC {
                            self.state = IACParseStateEnum::FindCommand;
                        } else {
                            if self.subnegotiation {
                                self.extra.push(byte);
                            } else {
                                out_buffer[o] = byte;
                                o += 1;
                            }
                        }
                    }
                    IACParseStateEnum::FindCommand => {
                        if byte == IAC {
                            // If we get two IACs in a row, it's an escaped IAC.
                            if self.subnegotiation {
                                self.extra.push(byte);
                            } else {
                                out_buffer[o] = byte;
                                o += 1;
                            }
                            self.state = IACParseStateEnum::FindIAC;
                        } else {
                            if !self.subnegotiation {
                                self.command = Some(byte);
                            }
                            let maybe_command = IACCommand::from_u8(byte);
                            match maybe_command {
                                Some(command) => {
                                    match command {
                                        // If we get a SB, DO, DONT, WILL, or WONT,
                                        // we need to look for an option.
                                        IACCommand::SB
                                            | IACCommand::DO
                                            | IACCommand::DONT
                                            | IACCommand::WILL
                                            | IACCommand::WONT => {
                                                self.state = IACParseStateEnum::FindOption;
                                            }
                                        _ => {
                                            if self.subnegotiation {
                                                if byte == IACCommand::SE as u8 {
                                                    stream.write(&out_buffer[..o])?;
                                                    o = 0;
                                                    fn_handle_iac(self.emit_iac().as_ref());
                                                    self.reset();
                                                } else {
                                                    Err(std::io::Error::new(
                                                            std::io::ErrorKind::Other,
                                                            "Unexpected IAC command in subnegotiation",
                                                    ))?;
                                                }
                                            } else {
                                                self.state = IACParseStateEnum::FindIAC;
                                                stream.write(&out_buffer[..o])?;
                                                o = 0;
                                                fn_handle_iac(self.emit_iac().as_ref());
                                                self.reset();
                                            }
                                        }
                                    }
                                }
                                None => {
                                    println!("Unknown IAC command: {}", byte);
                                    self.state = IACParseStateEnum::FindIAC;
                                }
                            }
                        }
                    }
                    IACParseStateEnum::FindOption => {
                        self.option = Some(byte);
                        if self.command.unwrap() == IACCommand::SB as u8 {
                            self.subnegotiation = true;
                            self.state = IACParseStateEnum::FindIAC;
                        } else {
                            stream.write(&out_buffer[..0])?;
                            o = 0;
                            fn_handle_iac(self.emit_iac().as_ref());
                            self.reset();
                        }
                    }
                }
                i += 1;
            }
            stream.write(&out_buffer[..o])?;
            Ok(())
        }
}

struct TelnetSession {
    stream: TcpStream,
    login_binary: String,
    setsid_binary: String,
    process: Option<Popen>,
    options: HashMap<IACOption, bool>,
}

fn openpty() -> (File, File) {
    let mut master: i32 = 0;
    let mut slave: i32 = 0;
    unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        /*let mut termios: libc::termios = std::mem::zeroed();
          libc::tcgetattr(master, &mut termios);
          termios.c_lflag &= !(libc::ECHO);
          termios.c_oflag |= libc::ONLCR | libc::XTABS;
          termios.c_iflag |= libc::ICRNL;
          termios.c_iflag &= !(libc::IXOFF);
          libc::tcsetattr(master, libc::TCSANOW, &termios);*/
    }
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    (master, slave)
}

impl TelnetSession {
    fn new(stream: TcpStream, login_binary: Option<String>) -> TelnetSession {
        let setsid_binary = which::which("setsid")
            .expect("setsid not found")
            .into_os_string()
            .into_string()
            .unwrap();
        let mut _login_binary: String;
        if login_binary.is_none() {
            _login_binary = which::which("login")
                .expect("login not found")
                .into_os_string()
                .into_string()
                .unwrap();
            } else {
                _login_binary = login_binary.unwrap();
        }
        TelnetSession {
            stream,
            process: None,
            // Set defaults options
            options: ([
                (IACOption::Echo, true),
                (IACOption::SuppressGoAhead, true),
                (IACOption::TerminalType, true),
                (IACOption::BinaryTransmission, true),
                (IACOption::NegotiateAboutWindowSize, true),
                (IACOption::RemoteFlowControl, true),
            ])
                .iter()
                .cloned()
                .collect(),
                login_binary: _login_binary,
                setsid_binary,
        }
    }

    fn run(&mut self) {
        // Open PTY
        let (master, slave) = openpty();
        let slave_reader = slave.try_clone().unwrap();
        let slave_writer = slave.try_clone().unwrap();
        // FInd the location of the setsid and login binaries
        self.process = Popen::create(
            &[&self.setsid_binary, &self.login_binary],
            PopenConfig {
                stdin: Redirection::File(slave_reader),
                stdout: Redirection::File(slave_writer),
                stderr: Redirection::Merge,
                ..Default::default()
            },
        )
            .ok();
        let pid = self
            .process
            .as_ref()
            .unwrap()
            .pid()
            .expect("Could not get PID");
        let mut pty = master.try_clone().unwrap();
        let mut stream = &self.stream.try_clone().unwrap();
        thread::scope(|s| {
            let mut pty = pty.try_clone().unwrap();
            let reader = s.spawn(move || {
                // Send IACs
                IAC::send_dont(IACOption::Echo, &mut stream);
                IAC::send_will(IACOption::Echo, &mut stream);
                IAC::send_do(IACOption::SuppressGoAhead, &mut stream);
                IAC::send_do(IACOption::TerminalType, &mut stream);
                IAC::send_will(IACOption::BinaryTransmission, &mut stream);
                IAC::send_do(IACOption::NegotiateAboutWindowSize, &mut stream);
                IAC::send_do(IACOption::RemoteFlowControl, &mut stream);
                IAC::send_do(IACOption::Linemode, &mut stream);
                let mut buffer = [0; 1024];
                loop {
                    let n = pty.read(&mut buffer);
                    match n {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                            // Double 255
                            let mut out_buffer = [0; 2048];
                            let mut o = 0;
                            for i in 0..n {
                                if buffer[i] == 255 {
                                    out_buffer[o] = 255;
                                    o += 1;
                                }
                                out_buffer[o] = buffer[i];
                                o += 1;
                            }
                            stream.write(&out_buffer[0..o]).unwrap();
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                            break;
                        }
                    }
                }
            });
            let options = &self.options;
            let mut pty = master.try_clone().unwrap();
            let writer = s.spawn(move || {
                let mut buffer = [0; 1024];
                let mut parser = IACParser::create();
                loop {
                    let n = stream.read(&mut buffer);
                    match n {
                        Ok(n) => {
                            if n == 0 {
                                break;
                            }
                            let inner_pty = pty.try_clone().unwrap();
                            parser
                                .parse_and_send(
                                    &buffer[..n],
                                    &mut pty,
                                    |iac: Result<&IAC, &std::io::Error>| -> () {
                                        match iac {
                                            Ok(iac) => {
                                                println!("IAC: {:?}", iac);
                                                match iac.command {
                                                    IACCommand::SB => {
                                                        println!(
                                                            "SB {:?} {:?}",
                                                            iac.option, iac.extra
                                                        );
                                                        match iac.option.as_ref() {
                                                            Some(
                                                                IACOption::NegotiateAboutWindowSize,
                                                            ) => {
                                                                let (width, height) =
                                                                    iac.get_naws();
                                                                println!(
                                                                    "NAWS: {}x{}",
                                                                    width, height
                                                                );
                                                                let raw_fd = inner_pty.as_raw_fd();
                                                                unsafe {
                                                                    libc::ioctl(
                                                                        raw_fd,
                                                                        libc::TIOCSWINSZ,
                                                                        &libc::winsize {
                                                                            ws_row: height as u16,
                                                                            ws_col: width as u16,
                                                                            ws_xpixel: 0,
                                                                            ws_ypixel: 0,
                                                                        },
                                                                    );
                                                                }
                                                                IAC::send(iac, &mut stream)
                                                                    .unwrap();
                                                                }
                                                            Some(IACOption::TerminalType) => {
                                                                IAC::send(iac, &mut stream)
                                                                    .unwrap();
                                                                }
                                                            Some(IACOption::Linemode) => {
                                                                // TODO! We should definitely parse this
                                                                println!("Linemode recieved but not parsed");
                                                                IAC::send(iac, &mut stream)
                                                                    .unwrap();
                                                                }
                                                            _ => {
                                                                println!("Unhandled SB: {:?}", iac);
                                                            }
                                                        }
                                                    }
                                                    IACCommand::DO => {
                                                        let option =
                                                            iac.option.expect("DO without option");
                                                        if options.contains_key(&option) {
                                                            if options[&option] {
                                                                IAC::send_will(option, &mut stream)
                                                                    .unwrap();
                                                                } else {
                                                                    IAC::send_wont(option, &mut stream)
                                                                        .unwrap();
                                                            }
                                                        } else {
                                                            IAC::send_wont(option, &mut stream)
                                                                .unwrap();
                                                            }
                                                    }
                                                    IACCommand::IP => {
                                                        println!(
                                                            "Interrupt, sending SIGINT to {}",
                                                            pid
                                                        );
                                                        unsafe {
                                                            let ret = libc::kill(
                                                                pid as i32,
                                                                libc::SIGINT,
                                                            );
                                                            if ret != 0 {
                                                                libc::perror(
                                                                    "kill\0".as_ptr() as *const i8
                                                                );
                                                            }
                                                        }
                                                    }
                                                    _ => {
                                                        println!("Unhandled IAC: {:?}", iac);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("Error: {}", e);
                                            }
                                        }
                                    },
                                    )
                                        .expect("Error parsing IAC");
                            }
                        Err(e) => {
                            println!("Error: {}", e);
                            break;
                        }
                    }
                }
            });
            println!("Threads started, waiting for process to finish");
            self.process
                .as_mut()
                .expect("Process not found")
                .wait()
                .unwrap();
            println!("Process finished");
            // Close the pty, this will cause the threads to exit
            unsafe {
                libc::close(master.as_raw_fd());
                libc::close(slave.as_raw_fd());
            }
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            reader.join().unwrap();
            writer.join().unwrap();
        });
        println!("Threads finished");
    }

    fn close(&mut self) {
        // Close the process
        self.process.take().unwrap().kill().unwrap();
    }
}

struct TelnetServer {
    listener: TcpListener,
    command: Option<String>,
}

impl TelnetServer {
    fn create(port: u16, bind_address: &str, command: Option<String>) -> TelnetServer {
        let listener = TcpListener::bind(format!("{}:{}", bind_address, port)).unwrap();
        TelnetServer { listener, command }
    }

    fn handle_connection(stream: TcpStream, command: Option<String>) {
        // Open a new thread to handle the connection
        // Create a new telnet session
        let mut session = TelnetSession::new(stream, command);
        // run the session
        session.run();
        println!("Connection closed!");
    }

    fn run(&mut self) {
        println!("Listening for connections");
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    println!("New connection: {}", stream.peer_addr().unwrap());
                    let command = self.command.clone();
                    thread::spawn(move || {
                        TelnetServer::handle_connection(stream, command);
                    });
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }
    }
}

struct CliOptions {
    port: u16,
    bind_address: String,
    command: Option<String>,
}

fn main() {
    let mut options = CliOptions {
        port: 23,
        bind_address: "127.0.0.1".to_string(),
        command: None,
    };
    {
        let mut parser = argparse::ArgumentParser::new();
        parser.refer(&mut options.port).add_option(
            &["-p", "--port"],
            argparse::Store,
            "Port to listen on",
        );
        parser.refer(&mut options.bind_address).add_option(
            &["-b", "--bind"],
            argparse::Store,
            "Address to bind to",
        );
        parser
            .refer(&mut options.command)
            .add_option(&["-c", "--command"],
                argparse::StoreOption, "Login command to run. If not specified, the system will search for the login binary in the path");
        parser.parse_args_or_exit();
    }
    println!("Starting telnet server");
    println!("Listening on {}:{}", options.bind_address, options.port);
    println!(
        "Command: {:?}",
        options.command.as_ref().unwrap_or(&("login".to_string()))
    );
    let mut server = TelnetServer::create(options.port, &options.bind_address, options.command);
    server.run();
}

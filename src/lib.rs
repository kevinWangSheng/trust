use std::{
    collections::{HashMap, VecDeque}, io::{self, Read, Write}, net::Ipv4Addr, os::linux::raw::stat, process::ExitStatus, sync::{Arc, Condvar, Mutex}, thread
};


mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

/// set the command to run 
pub fn run_command(cmd:&str,args:&[&str])->io::Result<ExitStatus>{
    use std::process::Command;
    let mut command = Command::new(cmd);
    command.args(args);
    let status = command.status()?;
    if !status.success() {
        let err_msg = format!(
            "Command `{} {}` failed with status: {}",
            cmd,
            args.join(" "),
            status
        );
        
        // 创建一个保留原始退出码的自定义错误
        let mut err = io::Error::new(
            io::ErrorKind::Other,
            err_msg,
        );
        
        // 如果有退出码，将其设置为原始错误码
        if let Some(code) = status.code() {
            // 在Windows上raw_os_error()和ExitStatus.code()是不同的，
            // 但在Unix系统上我们可以将exit code作为os_error
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    // 如果进程被信号终止，使用信号值作为错误码的高位
                    let combined_code = (signal << 8) | 0xFF;
                    err = io::Error::from_raw_os_error(combined_code);
                } else {
                    // 否则使用exit code作为错误码
                    err = io::Error::from_raw_os_error(code);
                }
            }
            
            #[cfg(windows)]
            {
                // Windows下简单地使用exit code
                err = io::Error::from_raw_os_error(code);
            }
        }
        
        return Err(err);
    }
    
    Ok(status)

}

// define a struct to hold the source and destination IP addresses and the port number
// this data was store in a hashmap
#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

type InterfaceHandle = Arc<Foobar>;
pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

#[derive(Default)]
pub struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    terminal: bool,
    pending: HashMap<u16, VecDeque<Quad>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        // set the terminal flag to true
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminal = true;
        drop(self.ih.take());

        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let mut buf = [0u8; 1504];
    
    loop {
        // we want to read from nic, but we want to make sure that we'll wake up when the next
        // timer has to be triggered!
        let mut pfd = [nix::poll::PollFd::new(
            nic.as_raw_fd(),
            nix::poll::EventFlags::POLLIN,
        )];
        let n = nix::poll::poll(&mut pfd[..], 10).map_err(|e| e.as_errno().unwrap())?;
        assert_ne!(n, -1);
        if n == 0 {
            let mut cmg = ih.manager.lock().unwrap();
            for connection in cmg.connections.values_mut() {
                // XXX: don't die on errors?
                connection.on_tick(&mut nic)?;
            }
            continue;
        }
        assert_eq!(n, 1);
        let nbytes = nic.recv(&mut buf[..])?;

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol().0 != 0x06 {
                    eprintln!("BAD PROTOCOL");
                    // not tcp, and continue
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = &mut *cmg;
                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };

                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                eprintln!("got packet for known quad {:?}", q);
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?;

                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all()
                                }
                                if a.contains(tcp::Available::WRITE) {
                                    // TODO: ih.snd_var.notify_all()
                                }
                            }
                            Entry::Vacant(e) => {
                                eprintln!("got packet for unknown quad {:?}", q);
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    eprintln!("listening, so accepting");
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.pending_var.notify_all()
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}

pub struct TcpListener{
    port: u16,
    h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();

        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active...");

        for quad in pending {
            // TODO need to notify the other end
            println!("dropping pending connection {:?}", quad);
        }
    }
}
impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            }

            cm = self.h.pending_var.wait(cm).unwrap();
        }
    }
    
}
impl Interface{
    pub fn new()->io::Result<Self>{
        // create the tun0 interface to receive the packet
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;


        let ih:InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
                packet_loop(nic, ih)
            })
        };
        Ok(Self{
            ih: Some(ih),
            jh: Some(jh)
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
        };
        drop(cm);
        Ok(TcpListener {
            port,
            h: self.ih.as_mut().unwrap().clone(),
        })
    }
}


pub struct TcpStream{
    quad:Quad,
    h:InterfaceHandle
}

// impl TcpStream for the read and write 

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block, because there won't be any more
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf[hread..(hread + tread)].copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }

            cm = self.h.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ))
        }
    }
}

impl TcpStream{
    // closed function

    pub fn shutdown(&self,how:std::net::Shutdown)->io::Result<()>{
        let mut cm = self.h.manager.lock().unwrap();

        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;
        // finaly colse the connection 
        c.close()
    }
}
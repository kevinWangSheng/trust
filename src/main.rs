use std::{
    io::{self, Read, Write},
    thread,
};

use anyhow::Ok;
use trust::run_command;

mod tcp;

fn main() -> anyhow::Result<()> {
    let interface_name = "tun0";
    let vitural_ip = "192.168.9.1";
    let route_ip = "192.168.8.0/24";
    let cdir_mask = 24;

    eprintln!(
        "Attempting to configure interface {} with IP {}/{}...",
        interface_name, vitural_ip, cdir_mask
    );

    // create a interface
    let mut interface = match trust::Interface::new() {
        io::Result::Ok(interface) => interface,
        Err(e) => {
            eprintln!("Failed to create interface: {}", e);
            return Err(e.into());
        }
    };

    #[cfg(target_os = "linux")]
    {
        match run_command(
            "ip",
            &[
                "route",
                "add",
                route_ip,
                "dev",
                interface_name,
                "src",
                vitural_ip,
            ],
        ) {
            io::Result::Ok(_) => {
                eprintln!("Route added successfully");
            }
            Err(e) => {
                let is_file_exist_error = if let Some(exit_code) = e.raw_os_error() {
                    exit_code == 2
                } else {
                    false
                };
                if is_file_exist_error{
                    eprintln!("you are already add the route, do not add it again");
                } else {
                    eprintln!("Failed to add route: {}", e);
                }
            }
        }
        if let Err(e) = run_command(
            "ip",
            &[
                "addr",
                "add",
                format!("{}", vitural_ip).as_str(),
                "dev",
                interface_name,
            ],
        ) {
            let is_file_exist_error = if let Some(exit_code) = e.raw_os_error() {
                exit_code == 2
            } else {
                false
            };
            let file_error = is_file_exist_error || e.kind() == io::ErrorKind::NotFound;
            if file_error {
                eprintln!("you are already add the ip, do not add it again");
            }
        }
        run_command("ip", &["link", "set", "dev", interface_name, "up"])?;
        eprintln!(
            "Interface {} configured with IP {}/{} successfully",
            interface_name, vitural_ip, cdir_mask
        );
    }
    // bind the listener
    let mut listener = interface.bind(443)?;
    eprintln!("Listening on port 443...");
    while let io::Result::Ok(mut stream) = listener.accept() {
        eprintln!("got connection!");
        stream.write(b"I send the repsonse to you!!\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        thread::spawn(move || {
            // stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }

    Ok(())
}

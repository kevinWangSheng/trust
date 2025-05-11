use std::{io::{self, Read, Write}, thread};

use anyhow::Ok;


mod tcp;
fn main() -> anyhow::Result<()> {
    // create a interface
    let mut interface = trust::Interface::new()?;

    // bind the listener
    let mut listener = interface.bind(443)?;
    while let io::Result::Ok(mut stream) = listener.accept() {
        eprintln!("got connection!");
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
                stream.write(b"I send the repsonse to you!!\n").unwrap();
            }
        });
    }

    Ok(())
}

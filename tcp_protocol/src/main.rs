use std::io;
use std::net::Ipv4Addr;

fn main() -> io::Result<()> {
    example_read_package_loop_parsing_flags_protocol_ignore_no_ipv4()
}

pub struct Ipv4Slice {
    protocol: u16
    source_addr: String
    destination_addr: String
    source_port: u16 
    destination_port: u16
}

fn parseSlice(buffer: &[u8]) -> Packet {
    let protocol = u16::from_be_bytes([buffer[0], buffer[1]]);
    let source_address = format!("{}.{}.{}.{}", buffer[12], buffer[13], buffer[14], buffer[15]);
    let destination_address = format!("{}.{}.{}.{}", buffer[16], buffer[17], buffer[18], buffer[19]);
    let source_port = Some(u16::from_be_bytes(&buffer[0..2].try_into().unwrap()))
    let destination_port = Some(u16::from_be_bytes(&buffer[2..4].try_into().unwrap()))

    return Ipv4Slice {
        protocol,
        source_address,
        destination_address,
        source_port,
        destination_port
    }
}

fn example_read_single_package() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    let nbytes = nic.recv(&mut buf[..])?;
    eprintln!("read {} bytes: {:x?}", nbytes, &buf[..nbytes]);
    Ok(())
}


fn example_read_package_loop() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        eprintln!("read {} bytes: {:x?}", nbytes, &buf[..nbytes]);
    }
    Ok(())
}


fn example_read_package_loop_parsing_flags_protocol() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        eprintln!(
            "read {} bytes (flags: {:x}, protocol: {:x}): {:x?}", nbytes - 4, flags, protocol, &buf[4..nbytes]);
    }
    Ok(())
}


fn example_read_package_loop_parsing_flags_protocol_ignore_no_ipv4() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);

        if protocol != 0x0800 {
            // no ipv4
            continue;
        }
        eprintln!(
            "read {} bytes (flags: {:x}, protocol: {:x}): {:x?}", nbytes - 4, flags, protocol, &buf[4..nbytes]);
    }
    Ok(())
}


fn example_read_package_loop_using_etherparser_flags_protocol_ignore_no_ipv4() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_protocol = u16::from_be_bytes([buf[2], buf[3]]);

        if eth_protocol != 0x0800 {
            // no ipv4
            continue;
        }

        match parseSlice(&buf[4..nbytes]) {
            Ok(p) => {
                // (src_ip, src_port, dst_ip, dst_port) -> quad
                let src = p.source_addr;
                let dst = p.destination_addr;
                let proto = p.protocol;
                eprintln!(
                    "{} -> {} {} bytes of protocol: {:x}", src, dst, p.payload_len(), proto);
            },
            Err(e) => {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
    Ok(())
}
pub mod options;
pub mod packet;

use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};

pub trait PacketHandler {
    fn handle_packet(&mut self, packet: packet::Packet) -> Option<packet::Packet>;
}

pub trait Socket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize>;
}

impl Socket for UdpSocket {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf)
    }

    fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        self.send_to(buf, addr)
    }
}

pub fn run_server(handler: &mut impl PacketHandler, workers: u16) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:67")?;
    socket.set_broadcast(true)?;
    run_server_with_socket(&socket, handler, workers)
}

pub fn run_server_with_socket(
    socket: &impl Socket,
    handler: &mut impl PacketHandler,
    _workers: u16,
) -> io::Result<()> {
    let mut buf = [0; 1500];

    loop {
        let (size, src) = socket.recv_from(&mut buf)?;

        let src_packet = match packet::Packet::try_from(&buf[..size]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", e);
                continue;
            }
        };

        process_packet(socket, handler, src_packet, src)?;
    }
}

fn process_packet(
    socket: &impl Socket,
    handler: &mut impl PacketHandler,
    src_packet: packet::Packet,
    src: SocketAddr,
) -> io::Result<()> {
    let src_broadcast = src_packet.broadcast_flag();
    let src_has_giaddr = !src_packet.giaddr.is_unspecified();

    if let Some(p) = handler.handle_packet(src_packet) {
        let data: Vec<u8> = (&p).into();

        if !src_has_giaddr && (src.ip().is_unspecified() || src_broadcast) {
            socket.send_to(
                data.as_slice(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), src.port()),
            )?;
        } else {
            // Has gateway address/unicast to client
            socket.send_to(data.as_slice(), src)?;
        }
    }

    Ok(())
}

use std::fmt;
use std::net::SocketAddr;
use std::num::Wrapping;
use tokio_io::codec::Decoder;
use bytes::BytesMut;
use bytes::BufMut;
use ip::IpHeader;

use super::TcpHeader;

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub struct ConnectionId {
    src: SocketAddr,
    dst: SocketAddr,
}

impl ConnectionId {
    pub fn new(ip: &IpHeader, tcp: &TcpHeader) -> ConnectionId {
        ConnectionId {
            src: SocketAddr::new(ip.source, tcp.src_port),
            dst: SocketAddr::new(ip.destination, tcp.dst_port),
        }
    }

    pub fn wrapped(self) -> ConnectionId {
        ConnectionId {
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    key: ConnectionId,
    state: TcpState,
}

#[derive(Debug, Clone, Copy)]
enum TcpState {
    Syn(u32, u32),
    SynAck(u32, u32, u32, u32),
    Established(u32, u32, u32, u32),
    // TODO: closing
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    ClientServer,
    ServerClient,
}

impl Connection {
    pub fn start(ip: &IpHeader, tcp: &TcpHeader) -> Option<Self> {
        if tcp.is_syn() && !tcp.is_ack() {
            assert_eq!(tcp.acknowledgement_number, 0);
            println!("C: SYN seq={} ack={}", tcp.sequence_number, tcp.acknowledgement_number);
            Some(Connection {
                key: ConnectionId::new(ip, tcp),
                state: TcpState::Syn(tcp.sequence_number, tcp.acknowledgement_number),
            })
        } else {
            None
        }
    }

    pub fn decoded<D: Decoder>(self, client_decoder: D, server_decoder: D) -> DecodedConnection<D> {
        DecodedConnection::new(self, client_decoder, server_decoder)
    }

    /// Returns Some(direction) if the data constains new data in direction.
    pub fn advance(&mut self, ip: &IpHeader, tcp: &TcpHeader, data: &[u8]) -> Option<Direction> {
        use std::cmp;
        use self::Direction::*;
        let dir = if self.key == ConnectionId::new(ip, tcp) { ClientServer } else { ServerClient };
        let data_len = Wrapping(data.len() as u32);

        self.state = match (self.state, dir, tcp.is_syn(), tcp.is_ack(), tcp.is_fin(), tcp.is_rst()) {
            (TcpState::Syn(cs, ca), ServerClient, true, true, false, false) => {
                //println!("S: SYN_ACK seq={} ack={}", tcp.sequence_number, tcp.acknowledgement_number);
                assert_eq!(cs, tcp.acknowledgement_number - 1);
                TcpState::SynAck(cs, ca,
                                 (Wrapping(tcp.sequence_number) + Wrapping(1)).0,
                                 (Wrapping(tcp.acknowledgement_number) + Wrapping(1)).0)
            },
            (TcpState::SynAck(cs, _, ss, sa), ClientServer, false, true, false, false) => {
                //println!("C: ACK seq={} ack={}", tcp.sequence_number, tcp.acknowledgement_number);
                assert_eq!((Wrapping(cs) + Wrapping(1)).0, tcp.sequence_number);
                assert_eq!(ss, tcp.acknowledgement_number);
                TcpState::Established(tcp.sequence_number, tcp.acknowledgement_number, ss, sa)
            },
            (TcpState::Established(cs, ca, ss, sa), ClientServer, false, true, false, false) => {
                //println!("C: EST ACK seq={} ack={} len={}", tcp.sequence_number, tcp.acknowledgement_number, data.len());
                if cs > tcp.sequence_number {
                    // retransmission, ignore data
                    return None;
                }
                assert_eq!(cs, tcp.sequence_number, "seq mismatch, diff = {}", cmp::max(cs, tcp.sequence_number) - cmp::min(cs, tcp.sequence_number));
                assert!(ss >= tcp.acknowledgement_number);
                assert!(ca <= ss, "ack does not match expected, diff = {}", if ca > ss { ca - ss } else { ss - ca });
                TcpState::Established((Wrapping(cs) + data_len).0, tcp.acknowledgement_number, ss, sa)
            }
            (TcpState::Established(cs, ca, ss, _), ServerClient, false, true, false, false) => {
                //println!("S: EST ACK seq={} ack={} len={}", tcp.sequence_number, tcp.acknowledgement_number, data.len());
                if ss > tcp.sequence_number {
                    // retransmission
                    return None;
                }

                assert_eq!(ss, tcp.sequence_number);
                //assert_eq!(cs, tcp.acknowledgement_number, "ack does not match expected, diff = {}", if cs > tcp.acknowledgement_number { cs - tcp.acknowledgement_number } else { tcp.acknowledgement_number - cs });
                assert!(tcp.acknowledgement_number <= cs, "ack does not match expected, diff = {}", if ca > ss { ca - ss } else { ss - ca });
                TcpState::Established(cs, ca, (Wrapping(ss) + data_len).0, tcp.acknowledgement_number)
            }
            (st, dir, syn, ack, fin, rst) => {
                panic!("unsupported transition with {} bytes, st = {:?}, dir = {:?}, syn = {}, ack = {}, fin = {}, rst = {}", data.len(), st, dir, syn, ack, fin, rst);
            }
        };

        Some(dir)
    }

    pub fn is_done(&self) -> bool {
        false
    }

    pub fn key(&self) -> ConnectionId {
        self.key
    }
}

pub struct DecodedConnection<D> {
    inner: Connection,
    client_side: ConnectionData<D>,
    server_side: ConnectionData<D>,
}

impl<D: Decoder> DecodedConnection<D> {
    fn new(connection: Connection, client_decoder: D, server_decoder: D) -> Self {
        DecodedConnection {
            inner: connection,
            client_side: ConnectionData::new(Direction::ClientServer, client_decoder),
            server_side: ConnectionData::new(Direction::ServerClient, server_decoder),
        }
    }

    pub fn advance(&mut self, ip: &IpHeader, tcp: &TcpHeader, data: &[u8]) {
        match self.inner.advance(ip, tcp, data) {
            Some(Direction::ClientServer) => self.client_side.push(data),
            Some(Direction::ServerClient) => self.server_side.push(data),
            None => {},
        }
        // TODO: eof handling when closing
    }

    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    pub fn key(&self) -> ConnectionId {
        self.inner.key()
    }

    pub fn decode(&mut self) -> Result<Option<(Direction, D::Item)>, D::Error> {
        if self.client_side.is_decodable() {
            if let Some(x) = self.client_side.decode()? {
                return Ok(Some(x));
            }
        }

        if self.server_side.is_decodable() {
            if let Some(x) = self.server_side.decode()? {
                return Ok(Some(x));
            }
        }

        Ok(None)
    }
}

struct ConnectionData<D> {
    direction: Direction,
    decodable: bool,
    decoder: D,
    buffer: BytesMut,
}

impl<D: Decoder> ConnectionData<D> {
    fn new(direction: Direction, decoder: D) -> Self {
        ConnectionData {
            direction,
            decodable: false,
            decoder,
            buffer: BytesMut::with_capacity(65536),
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.buffer.reserve(data.len());
        self.buffer.put(data);
        self.decodable = true;
    }

    fn is_decodable(&self) -> bool {
        self.decodable
    }

    fn decode(&mut self) -> Result<Option<(Direction, D::Item)>, D::Error> {
        assert!(self.decodable);
        match self.decoder.decode(&mut self.buffer) {
            Ok(None) => {
                self.decodable = false;
                Ok(None)
            },
            Ok(Some(x)) => Ok(Some((self.direction, x))),
            Err(e) => Err(e),
        }
    }
}

struct Hexdump<'x> {
    bytes: &'x [u8],
}

impl<'x> Hexdump<'x> {
    fn format_ascii(&self, fmt: &mut fmt::Formatter, start: usize, end: usize) -> fmt::Result {
        let group_len = 8;
        let mut char_count = 0;

        for i in start..end {
            let b = self.bytes[i];

            if 0x20 <= b && b < 0x7e {
                write!(fmt, "{}", b as char)?;
            } else {
                write!(fmt, ".")?;
            }

            char_count += 1;

            if i < end - 1 && char_count % group_len == 0 {
                write!(fmt, " ")?;
            }
        }

        Ok(())
    }
}

impl<'x> fmt::Debug for Hexdump<'x> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {

        let group_len = 4;
        let groups_per_line = 8;

        let bytes_per_line = group_len * groups_per_line;

        let mut count = 0;

        let prefix_len = (self.bytes.len() as f64).log10().ceil() as usize;


        for b in self.bytes[..].iter() {
            if count % bytes_per_line == 0 {
                write!(fmt, "0x{:01$x}: ", count, prefix_len)?;
            }

            let last = count == self.bytes.len() - 1;
            write!(fmt, "{:02x}", b)?;
            count += 1;
            if count % bytes_per_line == 0 {

                write!(fmt, " | ")?;

                self.format_ascii(fmt, (count - group_len * groups_per_line), count)?;

                writeln!(fmt)?;
            } else if !last {
                if count % group_len == 0 {
                    write!(fmt, "  ")?;
                } else {
                    write!(fmt, " ")?;
                }
            }
        }

        if count % bytes_per_line > 0 {

            let offset = count % 4;
            let end = (bytes_per_line - (count % bytes_per_line)) + offset;

            for i in offset..end {
                write!(fmt, "  ")?;

                if i % group_len == 0 {
                    write!(fmt, "  ")?;
                } else {
                    write!(fmt, " ")?;
                }
            }

            write!(fmt, " | ")?;

            self.format_ascii(fmt, (count - (count % bytes_per_line)), count)?;

            writeln!(fmt)?;
        }

        Ok(())
    }
}


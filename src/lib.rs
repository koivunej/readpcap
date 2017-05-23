extern crate byteorder;
extern crate bytes;
extern crate tokio_io;

pub mod pcap {
    use std::fmt;
    use std::io;
    use std::io::Read;
    use std::time::Duration;
    use byteorder::ReadBytesExt;
    use byteorder::LittleEndian;
    use byteorder::BigEndian;
    use byteorder::NetworkEndian;
    use byteorder::ByteOrder;

    #[derive(Debug)]
    pub enum Endianess {
        LE,
        BE,
    }

    #[derive(Debug)]
    pub struct Version {
        major: u16,
        minor: u16,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum DataLink {
        Unknown(u32),
        Ethernet,
    }

    impl DataLink {
        fn read_frame<'a>(&self, packet: &'a [u8]) -> Frame<'a> {
            match *self {
                DataLink::Ethernet => Frame::parse_ethernet(packet),
                _ => unimplemented!(),
            }
        }
    }

    pub struct MAC<'a>(&'a [u8]);

    impl<'a> fmt::Display for MAC<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            write!(fmt, "{:x}{:x}{:x}:{:x}{:x}{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
        }
    }

    impl<'a> fmt::Debug for MAC<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            <Self as fmt::Display>::fmt(self, fmt)
        }
    }

    #[derive(Debug)]
    pub enum Frame<'a> {
        Ethernet(EthernetFrame<'a>),
    }

    pub struct EthernetFrame<'a> {
        source: MAC<'a>,
        destination: MAC<'a>,
        len: u16,
        payload: &'a [u8],
    }

    impl<'a> fmt::Debug for EthernetFrame<'a> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_struct("EthernetFrame")
                .field("src", &self.source)
                .field("dst", &self.destination)
                .field("len", &self.len)
                .finish()
        }
    }

    struct Hexadecimal<T: fmt::LowerHex>(T);

    impl<T: fmt::LowerHex> fmt::Debug for Hexadecimal<T> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            write!(fmt, "{:x}", self.0)
        }
    }

    impl<'a> Frame<'a> {
        fn parse_ethernet(packet: &'a [u8]) -> Self {
            let len = match NetworkEndian::read_u16(&packet[12..14]) as usize {
                x if x <= 1500 => x,
                _ => packet.len() - 14,
            };
            Frame::Ethernet(EthernetFrame {
                source: MAC(&packet[0..6]),
                destination: MAC(&packet[6..12]),
                len: len as u16,
                payload: &packet[14..],
            })
        }

        pub fn body(&'a self) -> &'a [u8] {
            match self {
                &Frame::Ethernet(EthernetFrame { payload, .. }) => payload,
            }
        }
    }

    #[derive(Debug)]
    pub struct GlobalHeader {
        endianess: Endianess,
        nanosecond_timestamps: bool,
        version: Version,
        local_offset_seconds: i32,
        sigfigs: u32,
        snaplen: u32,
        datalink: DataLink,
    }

    #[derive(Debug)]
    pub struct PacketHeader {
        pub offset: Duration,
        recorded_len: u32,
        original_len: u32,
    }

    impl PacketHeader {
        pub fn is_full(&self) -> bool {
            self.recorded_len == self.original_len
        }

        pub fn read_packet_into<R: io::Read>(&self, reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
            let recorded_len = self.recorded_len as usize;

            if buf.len() < recorded_len {
                buf.reserve(recorded_len);
                unsafe { buf.set_len(recorded_len); }
            }

            reader.read_exact(&mut buf[..])
        }
    }

    impl GlobalHeader {
        pub fn read_packet_header<R: io::Read>(&self, reader: &mut R) -> io::Result<PacketHeader> {
            match self.endianess {
                Endianess::LE => read_packet_header::<LittleEndian, _>(self.nanosecond_timestamps, reader),
                Endianess::BE => read_packet_header::<BigEndian, _>(self.nanosecond_timestamps, reader),
            }
        }

        pub fn parse_frame<'a>(&self, buf: &'a [u8]) -> Frame<'a> {
            self.datalink.read_frame(buf)
        }
    }

    fn read_packet_header<E: ByteOrder, R: io::Read>(nanos: bool, reader: &mut R) -> io::Result<PacketHeader> {
        Ok(PacketHeader {
            offset: parse_packet_header_offset(reader.read_u32::<E>()?, reader.read_u32::<E>()?, nanos),
            recorded_len: reader.read_u32::<E>()?,
            original_len: reader.read_u32::<E>()?,
        })
    }

    fn parse_packet_header_offset(seconds: u32, subsec: u32, nanos: bool) -> Duration {
        if nanos {
            Duration::new(seconds as u64, subsec)
        } else {
            Duration::new(seconds as u64, subsec * 1_000)
        }
    }

    pub fn read_header<R: io::Read>(reader: &mut R) -> io::Result<GlobalHeader> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic[..])?;

        match LittleEndian::read_u32(&magic[..]) {
            0xa1b2c3d4 => read_header_rest::<LittleEndian, _>(Endianess::LE, false, reader),
            0xa1b23c4d => read_header_rest::<LittleEndian, _>(Endianess::LE, true, reader),
            0xd4c3b2a1 => read_header_rest::<BigEndian, _>(Endianess::BE, false, reader),
            0x4d3cb2a1 => read_header_rest::<BigEndian, _>(Endianess::BE, true, reader),
            x => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unexpected magic bytes: {:?}", x))),
        }
    }

    fn read_header_rest<E: ByteOrder, R: io::Read>(endianess: Endianess, nanos: bool, reader: &mut R) -> io::Result<GlobalHeader> {
        let major = reader.read_u16::<E>()?;
        let minor = reader.read_u16::<E>()?;

        let version = Version { major, minor };

        let local_offset_seconds = reader.read_i32::<E>()?;
        let sigfigs = reader.read_u32::<E>()?;
        let snaplen = reader.read_u32::<E>()?;
        let datalink = read_datalink::<E, _>(reader)?;

        Ok(GlobalHeader {
            endianess,
            nanosecond_timestamps: nanos,
            version,
            local_offset_seconds,
            sigfigs,
            snaplen,
            datalink,
        })
    }

    fn read_datalink<E: ByteOrder, R: io::Read>(reader: &mut R) -> io::Result<DataLink> {
        Ok(match reader.read_u32::<E>()? {
            1 => DataLink::Ethernet,
            x => DataLink::Unknown(x),
        })
    }

    pub fn parse_ip_header<'a>(buf: &'a [u8]) -> io::Result<(IpHeader, &'a [u8])> {
        let mut cursor = io::Cursor::new(buf);

        let (version, header_len) = {
            let byte = cursor.read_u8();
            (buf[0] >> 4, buf[0] & 0xf)
        };

        assert_eq!(version, 4);
        assert_eq!(header_len * 4, 20);

        let tos = cursor.read_u8();
        let total_len = cursor.read_u16::<NetworkEndian>()?;

        assert_eq!(total_len as usize, buf.len());

        let id = cursor.read_u16::<NetworkEndian>()?;
        let (flags, fragment_offset) = {
            let short = cursor.read_u16::<NetworkEndian>()?;
            (short >> 13, short & 0x1fff)
        };

        let ttl = cursor.read_u8()?;
        let protocol = cursor.read_u8()?;
        let checksum = cursor.read_u16::<NetworkEndian>()?;
        let src = cursor.read_u32::<NetworkEndian>()?;
        let dst = cursor.read_u32::<NetworkEndian>()?;

        Ok((IpHeader {
            version: IpVersion::Four,
            protocol: IpProto::from(protocol),
            ttl,
            source: Ipv4Addr::from(src).into(),
            destination: Ipv4Addr::from(dst).into(),
        }, &buf[header_len as usize * 4..]))
    }

    #[derive(Debug)]
    pub enum IpVersion {
        Four,
        Six,
    }

    use std::net::Ipv4Addr;
    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct IpHeader {
        pub version: IpVersion,
        pub protocol: IpProto,
        pub ttl: u8,
        pub source: IpAddr,
        pub destination: IpAddr,
    }

    #[derive(Debug, PartialEq)]
    pub enum IpProto {
        Udp,
        Tcp,
        Unknown(u8),
    }

    impl IpHeader {
        pub fn parse_headers<'a>(&self, buf: &'a [u8]) -> io::Result<(IpProtoHeaders, &'a [u8])> {
            match &self.protocol {
                &IpProto::Tcp => parse_tcp_headers(buf),
                _ => unimplemented!(),
            }
        }
    }

    impl From<u8> for IpProto {
        fn from(p: u8) -> Self {
            match p {
                17 => IpProto::Udp,
                6 => IpProto::Tcp,
                x => IpProto::Unknown(x),
            }
        }
    }

    #[derive(Debug)]
    pub enum IpProtoHeaders {
        Tcp(TcpHeader),
    }

    impl IpProtoHeaders {
        pub fn into_tcp_header(self) -> Result<TcpHeader, IpProtoHeaders> {
            match self {
                IpProtoHeaders::Tcp(x) => Ok(x),
                y => Err(y)
            }
        }
    }

    #[derive(Debug)]
    pub struct TcpHeader {
        pub src_port: u16,
        pub dst_port: u16,
        pub sequence_number: u32,
        pub acknowledgement_number: u32,
        pub offset: u8,
        pub reserved: u8,
        pub flags: u8,
        pub window: u16,
        pub checksum: u16,
        pub urgent_pointer: u16,
        // options: Vec<TcpOptionValue>,
    }

    impl TcpHeader {
        pub fn is_ack(&self) -> bool {
            self.flags & 0b0001_0000 != 0
        }
        pub fn is_psh(&self) -> bool {
            self.flags & 0b0000_1000 != 0
        }
        pub fn is_rst(&self) -> bool {
            self.flags & 0b0000_0100 != 0
        }
        pub fn is_syn(&self) -> bool {
            self.flags & 0b0000_0010 != 0
        }
        pub fn is_fin(&self) -> bool {
            self.flags & 0b0000_0001 != 0
        }
    }

    fn parse_tcp_headers<'a>(buf: &'a [u8]) -> io::Result<(IpProtoHeaders, &'a [u8])> {
        let mut cursor = io::Cursor::new(buf);

        let src_port = cursor.read_u16::<NetworkEndian>()?;
        let dst_port = cursor.read_u16::<NetworkEndian>()?;
        let sequence_number = cursor.read_u32::<NetworkEndian>()?;
        let acknowledgement_number = cursor.read_u32::<NetworkEndian>()?;
        let (offset, reserved) = {
            let byte = cursor.read_u8()?;
            (byte >> 4, byte & 0xf)
        };
        let flags = cursor.read_u8()?;
        let window = cursor.read_u16::<NetworkEndian>()?;
        let checksum = cursor.read_u16::<NetworkEndian>()?;
        let urgent_pointer = cursor.read_u16::<NetworkEndian>()?;

        let len = offset as usize * 4;

        if len > 20 {
            // options
            for i in 0..(len - 20) { cursor.read_u8()?; }
        }

        let pos = cursor.position() as usize;
        assert_eq!(pos, len);

        Ok((IpProtoHeaders::Tcp(TcpHeader {
            src_port,
            dst_port,
            sequence_number,
            acknowledgement_number,
            offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_pointer,
            // options
        }), &buf[pos..]))
    }
}

pub mod tcp {
    use std::net::SocketAddr;
    use std::num::Wrapping;
    use tokio_io::codec::Decoder;
    use bytes::BytesMut;

    use pcap::IpHeader;
    use pcap::TcpHeader;

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
    pub struct Connection<D> {
        key: ConnectionId,
        state: TcpState,
        decoder: D,
        client_buffer: BytesMut,
        server_buffer: BytesMut,
        client_readable: bool,
        server_readable: bool,
        decodes: usize,
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

    impl<D: Decoder> Connection<D> {
        pub fn start(ip: &IpHeader, tcp: &TcpHeader, decoder: D) -> Option<Self> {
            if tcp.is_syn() && !tcp.is_ack() {
                assert_eq!(tcp.acknowledgement_number, 0);
                println!("C: SYN seq={} ack={}", tcp.sequence_number, tcp.acknowledgement_number);
                Some(Connection {
                    key: ConnectionId::new(ip, tcp),
                    state: TcpState::Syn(tcp.sequence_number, tcp.acknowledgement_number),
                    decoder,
                    client_buffer: BytesMut::with_capacity(16 * 1024),
                    server_buffer: BytesMut::with_capacity(16 * 1024),
                    client_readable: false,
                    server_readable: false,
                    decodes: 0,
                })
            } else {
                None
            }
        }

        pub fn advance(&mut self, ip: &IpHeader, tcp: &TcpHeader, data: &[u8]) {
            use std::cmp;
            use bytes::BufMut;
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
                (TcpState::SynAck(cs, ca, ss, sa), ClientServer, false, true, false, false) => {
                    //println!("C: ACK seq={} ack={}", tcp.sequence_number, tcp.acknowledgement_number);
                    assert_eq!((Wrapping(cs) + Wrapping(1)).0, tcp.sequence_number);
                    assert_eq!(ss, tcp.acknowledgement_number);
                    TcpState::Established(tcp.sequence_number, tcp.acknowledgement_number, ss, sa)
                },
                (TcpState::Established(cs, ca, ss, sa), ClientServer, false, true, false, false) => {
                    //println!("C: EST ACK seq={} ack={} len={}", tcp.sequence_number, tcp.acknowledgement_number, data.len());
                    if cs > tcp.sequence_number {
                        // retransmission, ignore data
                        return;
                    }
                    assert_eq!(cs, tcp.sequence_number, "seq mismatch, diff = {}", cmp::max(cs, tcp.sequence_number) - cmp::min(cs, tcp.sequence_number));
                    assert!(ss >= tcp.acknowledgement_number);
                    assert!(ca <= ss, "ack does not match expected, diff = {}", if ca > ss { ca - ss } else { ss - ca });
                    TcpState::Established((Wrapping(cs) + data_len).0, tcp.acknowledgement_number, ss, sa)
                }
                (TcpState::Established(cs, ca, ss, sa), ServerClient, false, true, false, false) => {
                    //println!("S: EST ACK seq={} ack={} len={}", tcp.sequence_number, tcp.acknowledgement_number, data.len());
                    if ss > tcp.sequence_number {
                        // retransmission
                        return;
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

            if data.is_empty() {
                return;
            }

            let ref mut buf = match dir {
                ClientServer => {
                    self.client_readable = true;
                    &mut self.client_buffer
                },
                ServerClient => {
                    self.server_readable = true;
                    &mut self.server_buffer
                }
            };

            buf.reserve(data.len());
            buf.put(data);

            // TODO: eof handling when closing
        }

        pub fn decode(&mut self) -> Result<Option<(Direction, D::Item)>, D::Error> {
            self.decodes += 1;
            if self.client_readable {
                /*println!("{} Decoding from Client -> Server:", self.decodes);
                if self.decodes == 588 {
                    println!("Decoding from Client -> Server:\n{:?}", Hexdump { bytes: &self.client_buffer[..] });
                }*/
                match self.decoder.decode(&mut self.client_buffer) {
                    Ok(None) => {},
                    Ok(Some(x)) => return Ok(Some((Direction::ClientServer, x))),
                    Err(e) => return Err(e),
                }
                self.client_readable = false;
            }

            if self.server_readable {
                match self.decoder.decode(&mut self.server_buffer) {
                    Ok(None) => {},
                    Ok(Some(x)) => return Ok(Some((Direction::ServerClient, x))),
                    Err(e) => return Err(e),
                }
                self.server_readable = false;
            }

            Ok(None)
        }

        pub fn is_done(&self) -> bool {
            false
        }

        pub fn key(&self) -> ConnectionId {
            self.key
        }
    }

    use std::fmt;

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

}

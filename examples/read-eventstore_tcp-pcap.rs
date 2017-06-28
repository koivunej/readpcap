extern crate readpcap;
extern crate eventstore_tcp;

use std::io;
use std::env;
use std::fs;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use readpcap::pcap;
use readpcap::ip::IpProto;
use readpcap::ip::parse_ip_header;
use readpcap::tcp::ConnectionId;
use readpcap::tcp::Connection;
use readpcap::tcp::Direction::*;

use eventstore_tcp::codec::PackageCodec;
use eventstore_tcp::package::Package;

fn main() {
    let filename = env::args().skip(1).next().unwrap_or_else(|| panic!("INPUT argument required"));
    let mut file = fs::File::open(filename).expect("Failed to open INPUT file");

    print_operation_durations(&mut file).unwrap();
}

fn print_operation_durations(file: &mut fs::File) -> io::Result<()> {

    let header = pcap::GlobalHeader::read_from(file)?;

    // keep a map of ConnectionId => Connection
    let mut conn_map = HashMap::new();

    // when protocol level operation started
    let mut operations = HashMap::new();
    let mut decoded = [0u32, 0u32];

    // buffer for packet data ...
    // TODO: use mmap
    let mut buf = Vec::new();

    // for printing relative time offsets, keep the first timestamp
    let mut first_offset = None;

    loop {
        buf.clear();

        let packet_header = match header.read_packet_header(file) {
            Ok(hdr) => hdr,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        assert!(packet_header.is_full());
        first_offset = first_offset.or(Some(packet_header.offset));

        let elapsed = packet_header.offset - first_offset.unwrap();

        packet_header.read_packet_into(file, &mut buf).unwrap();

        let frame = header.parse_frame(&buf);
        let (ipheader, next) = parse_ip_header(frame.body()).unwrap();

        if ipheader.protocol != IpProto::Tcp {
            continue;
        }

        let (tcpheader, next) = ipheader.parse_headers(next).unwrap();
        let tcpheader = tcpheader.into_tcp_header().unwrap();

        let key = ConnectionId::new(&ipheader, &tcpheader);

        let remove = {
            // this mapping is probably wrong in some cases but haven't figured out a better one.
            // basically store the connection with key = (client_addr, server_addr) but try to find
            // it with (server_addr, client_addr) as well.
            let mut connection = if conn_map.contains_key(&key.wrapped()) {
                conn_map.get_mut(&key.wrapped()).unwrap()
            } else if conn_map.contains_key(&key) {
                conn_map.get_mut(&key).unwrap()
            } else if let Some(conn) = Connection::start(&ipheader, &tcpheader) {
                // wrap the created connection with these decoders in ClientServer, ServerClient
                // directions. note that the connection is created on first SYN so it's not really
                // a full tcp connection but hopefully it will become one.
                let wrapped = conn.decoded(PackageCodec, PackageCodec);

                match conn_map.entry(key) {
                    Entry::Vacant(ve) => Some(ve.insert(wrapped)),
                    _ => panic!("Entry cannot be occupied as we just checked it"),
                };

                assert!(next.is_empty(), "connection contains data on first SYN");
                continue;
            } else {
                // unknown connection, and packet capture does not contain data for its start
                continue;
            };

            connection.advance(&ipheader, &tcpheader, next);

            loop {
                // code below assumes there is nothing server initiated
                match connection.decode().unwrap() {
                    None => break,
                    Some((ClientServer, Package { correlation_id, .. })) => {
                        assert_eq!(operations.insert(correlation_id, elapsed), None);
                        decoded[0] += 1;
                    },
                    Some((ServerClient, Package { correlation_id, .. })) => {
                        // print an estimate for operation delay by using the capture timestamps
                        let elapsed = elapsed - operations.remove(&correlation_id).unwrap();
                        decoded[1] += 1;
                        println!("{}", elapsed.as_secs() * 1_000 + elapsed.subsec_nanos() as u64 / 1_000_000);
                    }
                }
            }

            if connection.is_done() {
                Some(connection.key())
            } else {
                None
            }
        };

        if let Some(key) = remove {
            conn_map.remove(&key);
        }
    }

    if !conn_map.is_empty() {
        eprintln!("Packet capture ended before with {} remaining connections:", conn_map.len());
        for (key, _) in conn_map {
            eprintln!("  => {:?}", key);
        }
    }

    eprintln!("Decoded frames: ClientServer {}, ServerClient {}", decoded[0], decoded[1]);

    Ok(())
}

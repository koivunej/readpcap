extern crate byteorder;
extern crate bytes;
extern crate tokio_io;

pub mod pcap;
pub mod ip;
pub mod tcp;

pub mod tracking {
    use std::collections::HashMap;
    use tcp::ConnectionId;
    use tcp::Connection;

    pub struct NaiveTcpConnectionTracker {
        connections: HashMap<ConnectionId, Connection>,
    }
}

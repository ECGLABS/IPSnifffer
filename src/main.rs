use clap::{Arg, Command};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::{Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};

fn main() {
    let matches = Command::new("IP Sniffer")
        .version("0.1.0")
        .author("Your Name <your@email.com>")
        .about("Sniffs IP packets on the specified network interface")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("IFACE")
                .help("Sets the network interface to use")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("filter")
                .short('f')
                .long("filter")
                .value_name("PROTOCOL")
                .help("Filter by protocol (e.g. tcp, udp, icmp)")
                .takes_value(true),
        )
        .get_matches();

    let iface_name = matches.value_of("interface").unwrap();
    let filter = matches.value_of("filter");

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == iface_name)
        .expect("Error: Interface not found");

    println!("Sniffing on interface: {}", iface_name);
    if let Some(f) = filter {
        println!("Protocol filter: {}", f);
    }

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                        match filter {
                            Some("tcp") if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp => continue,
                            Some("udp") if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp => continue,
                            Some("icmp") if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp => continue,
                            _ => {}
                        }

                        println!(
                            "IP Packet: {} -> {} | Protocol: {:?}",
                            ip_packet.get_source(),
                            ip_packet.get_destination(),
                            ip_packet.get_next_level_protocol()
                        );
                    }
                }
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}

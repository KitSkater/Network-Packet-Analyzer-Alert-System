

import scapy.all as scapy
from datetime import datetime

def auto_detect_interface():
    interfaces = scapy.get_if_list()
    for iface in interfaces:
        # Skip loopback or tunnel interfaces
        if "loopback" in iface.lower() or "pseudo" in iface.lower():
            continue
        return iface
    raise RuntimeError("No valid network interface found!")

def packet_handler(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {packet.summary()}")

def start_sniffing(interface=None, packet_count=0):
    if not interface:
        interface = auto_detect_interface()
    print(f"\n📡 Starting live capture on interface: {interface}")
    print("🔴 Press Ctrl+C to stop.\n")
    scapy.sniff(iface=interface, prn=packet_handler, store=False, count=packet_count)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="🕵️ Raspberry Pi Network Packet Sniffer (Level 1)")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface to sniff on (auto-detects if not provided)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")

    args = parser.parse_args()
    try:
        start_sniffing(interface=args.interface, packet_count=args.count)
    except PermissionError:
        print("❌ Error: Permission denied. Run as Administrator or with sudo.")
    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user.")
    except Exception as e:
        print(f"❌ Error: {e}")
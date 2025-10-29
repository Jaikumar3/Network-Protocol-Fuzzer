#!/usr/bin/env python3
# filepath: c:\Users\z004vrtj\Desktop\Jes\python
import argparse
import ipaddress
import socket
import os
import platform
from boofuzz import Session, Target, TCPSocketConnection, UDPSocketConnection
from boofuzz import s_initialize, s_string, s_block_start, s_block_end, s_static, s_delim, s_get
import subprocess

def get_output_directory():
    """Get appropriate output directory based on operating system"""
    system = platform.system().lower()
    
    if system == "windows":
        # Windows paths
        possible_paths = [
            os.path.expanduser("~/Documents/Jai pentest"),
            os.path.expanduser("~/Desktop/Jai pentest"),
            "C:/Temp/Jai pentest",
            "C:/Users/Public/Documents/Jai pentest"
        ]
    else:
        # Linux/Unix paths
        possible_paths = [
            os.path.expanduser("~/jai_pentest"),
            "/tmp/jai_pentest",
            "/var/tmp/jai_pentest",
            os.path.expanduser("~/Documents/jai_pentest")
        ]
    
    # Try to find/create a writable directory
    for path in possible_paths:
        try:
            os.makedirs(path, exist_ok=True)
            # Test write permissions
            test_file = os.path.join(path, "test_write.tmp")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            print(f"[+] Using output directory: {path}")
            return path
        except (OSError, PermissionError):
            continue
    
    # Fallback to current directory
    fallback = os.path.join(os.getcwd(), "fuzz_results")
    os.makedirs(fallback, exist_ok=True)
    print(f"[!] Using fallback directory: {fallback}")
    return fallback

def validate_ip_address(ip_str):
    """Validate and classify IP address (IPv4 or IPv6)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4", str(ip)
        elif isinstance(ip, ipaddress.IPv6Address):
            return "ipv6", str(ip)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip_str}")

class IPv6TCPSocketConnection(TCPSocketConnection):
    """TCP connection with IPv6 support"""
    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0):
        super().__init__(host, port, send_timeout, recv_timeout)
        self._host = host
        self._port = port
    
    def open(self):
        """Open IPv6 TCP connection"""
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._sock.settimeout(self._send_timeout)
        self._sock.connect((self._host, self._port))

class IPv6UDPSocketConnection(UDPSocketConnection):
    """UDP connection with IPv6 support"""
    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, bind_port=0):
        super().__init__(host, port, send_timeout, recv_timeout)
        self._host = host
        self._port = port
        self._bind_port = bind_port
        # Set bind address for receiving data
        self.bind = ("::", bind_port)  # IPv6 any address
    
    def open(self):
        """Open IPv6 UDP connection"""
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._sock.settimeout(self._send_timeout)
        # Bind to receive responses
        if self.bind:
            try:
                self._sock.bind(self.bind)
                print(f"[+] Bound to IPv6 address {self.bind}")
            except Exception as e:
                print(f"[!] Bind failed, using connect only: {e}")
        # Connect to target
        self._sock.connect((self._host, self._port))

def create_connection(ip, port, protocol, ip_version, timeout=5):
    """Create connection with IPv6 support"""
    if protocol == "tcp":
        if ip_version == "ipv6":
            connection = IPv6TCPSocketConnection(ip, port, send_timeout=timeout, recv_timeout=timeout)
        else:
            connection = TCPSocketConnection(ip, port, send_timeout=timeout, recv_timeout=timeout)
    else:  # UDP
        if ip_version == "ipv6":
            # Use a random high port for binding to receive responses
            import random
            bind_port = random.randint(49152, 65535)
            connection = IPv6UDPSocketConnection(ip, port, send_timeout=timeout, recv_timeout=timeout, bind_port=bind_port)
        else:
            # For IPv4 UDP, set bind address
            connection = UDPSocketConnection(ip, port, send_timeout=timeout, recv_timeout=timeout)
            # Set bind for IPv4 as well
            import random
            bind_port = random.randint(49152, 65535)
            connection.bind = ("0.0.0.0", bind_port)
    
    return connection

def main():
    parser = argparse.ArgumentParser(description="Fuzz a target service with IPv4/IPv6 support.")
    parser.add_argument("--ip", required=True, help="Target IP address (IPv4 or IPv6).")
    parser.add_argument("--port", type=int, required=True, help="Target port.")
    parser.add_argument("--protocol", choices=["tcp", "udp"], required=True, help="Protocol (tcp or udp).")
    parser.add_argument("--ipv6-only", action="store_true", help="Force IPv6 only mode.")
    parser.add_argument("--dual-stack", action="store_true", help="Test both IPv4 and IPv6 if available.")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout (seconds).")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel scanning with unique outputs.")
    parser.add_argument("--output-dir", help="Custom output directory (overrides auto-detection).")

    args = parser.parse_args()

    # Get output directory (cross-platform)
    if args.output_dir:
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
        print(f"[+] Using custom output directory: {output_dir}")
    else:
        output_dir = get_output_directory()

    # Create timestamp for unique output naming
    import time
    timestamp = int(time.time())
    
    # Validate and classify IP address
    ip_version, validated_ip = validate_ip_address(args.ip)
    
    print(f"[*] Operating System: {platform.system()} {platform.release()}")
    print(f"[*] Target: {validated_ip} ({ip_version.upper()})")
    print(f"[*] Port: {args.port}")
    print(f"[*] Protocol: {args.protocol.upper()}")
    print(f"[*] Output Directory: {output_dir}")
    
    print(f"[*] Operating System: {platform.system()} {platform.release()}")
    print(f"[*] Target: {validated_ip} ({ip_version.upper()})")
    print(f"[*] Port: {args.port}")
    print(f"[*] Protocol: {args.protocol.upper()}")
    print(f"[*] Output Directory: {output_dir}")
    
    # Check IPv6 requirements
    if args.ipv6_only and ip_version != "ipv6":
        print("[!] Error: --ipv6-only specified but target is not IPv6")
        return
    
    # Handle dual-stack testing
    targets_to_test = []
    if args.dual_stack:
        if ip_version == "ipv4":
            # Try to find IPv6 equivalent (this is a simple example)
            targets_to_test = [(validated_ip, "ipv4")]
            print("[*] Dual-stack mode: Testing IPv4 only (no IPv6 equivalent found)")
        else:
            targets_to_test = [(validated_ip, "ipv6")]
            print("[*] Dual-stack mode: Testing IPv6 only")
    else:
        targets_to_test = [(validated_ip, ip_version)]

    for target_ip, target_version in targets_to_test:
        print(f"\n[*] Testing {target_ip} ({target_version.upper()})")
        
        # Create cross-platform output paths
        if args.parallel:
            # Use timestamp and target info for unique naming
            safe_ip = target_ip.replace(":", "_").replace(".", "_")
            unique_id = f"{safe_ip}_{args.port}_{timestamp}"
            db_filename = f"{args.protocol}_{target_version}_{unique_id}_fuzz_results.db"
            report_filename = f"{args.protocol}_{target_version}_{unique_id}_boofuzz_report.html"
        else:
            # Standard naming for single scans
            db_filename = f"{args.protocol}_{target_version}_fuzz_results.db"
            report_filename = f"{args.protocol}_{target_version}_boofuzz_report.html"
        
        # Use os.path.join for cross-platform compatibility
        db_path = os.path.join(output_dir, db_filename)
        report_path = os.path.join(output_dir, report_filename)
        
        print(f"[*] Database: {db_path}")
        print(f"[*] Report will be: {report_path}")

        # Create IPv6-aware connection
        try:
            connection = create_connection(target_ip, args.port, args.protocol, target_version, args.timeout)
            print(f"[+] Created {target_version.upper()} {args.protocol.upper()} connection")
        except Exception as e:
            print(f"[!] Failed to create connection: {e}")
            continue

        session = Session(
            session_filename=db_path,
            target=Target(connection=connection),
            receive_data_after_fuzz=False,  # Disable receive to avoid UDP bind issues
            check_data_received_each_request=False  # Disable response checking
        )

        # Enhanced fuzzing templates for IPv6
        fuzz_name = f"{args.protocol.upper()}_{target_version.upper()}_FUZZ"
        s_initialize(fuzz_name)
        
        if s_block_start("Request"):
            if target_version == "ipv6":
                # IPv6-specific fuzzing patterns
                s_string("IPv6_CMD", fuzzable=True, max_len=1024)
                s_delim(" ", fuzzable=False)
                s_string("IPv6_ARG", fuzzable=True, max_len=2048)
                # Add IPv6 address fuzzing
                s_delim(" ", fuzzable=False)
                s_string(target_ip, name="ipv6_addr", fuzzable=True)
            else:
                # Standard IPv4 fuzzing
                s_string("CMD", fuzzable=True)
                s_delim(" ", fuzzable=False)
                s_string("ARG", fuzzable=True)
            s_static("\r\n")
        s_block_end()

        try:
            session.connect(s_get(fuzz_name))
            print(f"[*] Starting fuzz session for {target_version.upper()}...")
            session.fuzz()
            print(f"[+] Fuzzing completed for {target_ip}")
        except Exception as e:
            print(f"[!] Fuzzing failed for {target_ip}: {e}")
            continue

        # Generate HTML report after fuzzing
        print(f"\n[*] Generating HTML report for {target_version.upper()}...")
        try:
            subprocess.run(["boofuzz-html-report", db_path, "-o", report_path], check=True)
            print(f"[+] Report saved as {report_path}")
        except Exception as e:
            print(f"[!] Failed to generate report: {e}")

if __name__ == "__main__":
    main()

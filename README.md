# IPv4/IPv6 Network Fuzzer Tool

## 🎯 Overview

This advanced network fuzzing tool provides comprehensive security testing capabilities for both IPv4 and IPv6 networks using TCP and UDP protocols. Built on the boofuzz framework, it offers protocol-aware fuzzing with enhanced IPv6 support for modern network security assessments.

## 🚀 Features

- **Dual-Stack Support**: IPv4 and IPv6 fuzzing capabilities
- **Protocol Support**: TCP and UDP transport layers
- **Advanced IPv6 Handling**: Native IPv6 socket management
- **Parallel Scanning**: Unique output files prevent conflicts
- **Protocol Detection**: Automatic IP version classification
- **Custom Payloads**: Enhanced fuzzing templates for IPv6
- **Comprehensive Reporting**: HTML reports with detailed analysis

## 📋 Requirements

```bash
pip install boofuzz
pip install ipaddress  # Built into Python 3.3+
```

## 🔧 Installation

1. Clone or download the script
2. Install dependencies
3. Ensure proper network permissions (may require admin/root for raw sockets)

## 📖 Usage

### Basic Usage

```bash
# IPv4 TCP Fuzzing
python ipv6_fuzzer.py --ip 192.168.1.100 --port 80 --protocol tcp

# IPv6 UDP Fuzzing  
python ipv6_fuzzer.py --ip fd35:156e:94e2:1:e622:98f1:b8b8:64cc --port 5683 --protocol udp

# IPv6 with timeout
python ipv6_fuzzer.py --ip 2001:db8::1 --port 443 --protocol tcp --timeout 10
```

### Advanced Options

```bash
# IPv6 Only Mode
python ipv6_fuzzer.py --ip ::1 --port 22 --protocol tcp --ipv6-only

# Parallel Safe Mode (for multiple instances)
python ipv6_fuzzer.py --ip target::1 --port 80 --protocol udp --parallel

# Dual Stack Testing
python ipv6_fuzzer.py --ip 192.168.1.1 --port 443 --protocol tcp --dual-stack
```

## 🏗️ Architecture Deep Dive

### 1. IP Address Validation & Classification

```python
def validate_ip_address(ip_str):
    """Automatically detects and validates IPv4/IPv6 addresses"""
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv4Address):
        return "ipv4", str(ip)
    elif isinstance(ip, ipaddress.IPv6Address):
        return "ipv6", str(ip)
```

**Process:**
1. Input validation using Python's `ipaddress` module
2. Automatic classification as IPv4 or IPv6
3. Address normalization and formatting
4. Error handling for malformed addresses

### 2. Connection Management

#### IPv4 Connections
```python
# Standard boofuzz connections
connection = TCPSocketConnection(ip, port)  # IPv4 TCP
connection = UDPSocketConnection(ip, port)  # IPv4 UDP
```

#### IPv6 Connections (Custom Implementation)
```python
class IPv6TCPSocketConnection(TCPSocketConnection):
    def open(self):
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._sock.connect((self._host, self._port))

class IPv6UDPSocketConnection(UDPSocketConnection):
    def open(self):
        self._sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self._sock.bind(("::", random_port))  # IPv6 any address
        self._sock.connect((self._host, self._port))
```

**Key Differences:**
- **IPv4**: Uses `AF_INET` socket family
- **IPv6**: Uses `AF_INET6` socket family
- **UDP Binding**: IPv6 uses `"::"` (any), IPv4 uses `"0.0.0.0"`

### 3. Payload Construction

#### Template Structure
```python
s_initialize("PROTOCOL_VERSION_FUZZ")
s_block_start("Request"):
    # Protocol-specific fields
    s_string("COMMAND", fuzzable=True, max_len=size)
    s_delim(" ", fuzzable=False)
    s_string("ARGUMENT", fuzzable=True, max_len=size)
    s_static("\r\n")
s_block_end()
```

#### IPv4 vs IPv6 Payload Differences

**IPv4 Fuzzing Template:**
```python
s_string("CMD", fuzzable=True)           # Standard command field
s_delim(" ", fuzzable=False)             # Space delimiter
s_string("ARG", fuzzable=True)           # Standard argument field
s_static("\r\n")                         # Line terminator
```

**IPv6 Fuzzing Template:**
```python
s_string("IPv6_CMD", fuzzable=True, max_len=1024)    # Larger command field
s_delim(" ", fuzzable=False)                         # Space delimiter  
s_string("IPv6_ARG", fuzzable=True, max_len=2048)    # Larger argument field
s_delim(" ", fuzzable=False)                         # Space delimiter
s_string(target_ip, name="ipv6_addr", fuzzable=True) # IPv6 address fuzzing
s_static("\r\n")                                     # Line terminator
```

**Size Differences:**
- **IPv4**: Default boofuzz sizes (typically 256-512 bytes)
- **IPv6**: Enhanced sizes (1024-2048 bytes) for larger address space testing

## 📦 Packet Structure Analysis

### IPv4 UDP Packet Structure
```
┌─────────────────────────────────┐
│      IPv4 Header (20 bytes)     │
├─────────────────────────────────┤
│ Version: 4                      │
│ Header Length: 5 (20 bytes)     │
│ Type of Service: 0              │
│ Total Length: [Header + Data]   │
│ Identification: [Random]        │
│ Flags: 0x4000 (Don't Fragment)  │
│ Fragment Offset: 0              │
│ Time to Live: 64                │
│ Protocol: 17 (UDP)              │
│ Header Checksum: [Calculated]   │
│ Source IP: [Your IPv4]          │
│ Destination IP: [Target IPv4]   │
├─────────────────────────────────┤
│      UDP Header (8 bytes)       │
├─────────────────────────────────┤
│ Source Port: [Random 49152+]    │
│ Destination Port: [Target]      │
│ Length: [Header + Payload]      │
│ Checksum: [Calculated]          │
├─────────────────────────────────┤
│         Payload Data            │
├─────────────────────────────────┤
│ "CMD ARG\r\n"                   │
│ [Fuzzed content varies]         │
└─────────────────────────────────┘
```

### IPv6 UDP Packet Structure
```
┌─────────────────────────────────────────┐
│          IPv6 Header (40 bytes)         │
├─────────────────────────────────────────┤
│ Version: 6                              │
│ Traffic Class: 0                        │
│ Flow Label: 0                           │
│ Payload Length: [UDP Header + Data]     │
│ Next Header: 17 (UDP)                   │
│ Hop Limit: 64                           │
│ Source Address: [Your IPv6] (16 bytes)  │
│ Dest Address: [Target IPv6] (16 bytes)  │
├─────────────────────────────────────────┤
│          UDP Header (8 bytes)           │
├─────────────────────────────────────────┤
│ Source Port: [Random 49152-65535]       │
│ Destination Port: [Target Port]         │
│ Length: [Header + Payload Length]       │
│ Checksum: [IPv6 Pseudo-header + Data]   │
├─────────────────────────────────────────┤
│            Payload Data                 │
├─────────────────────────────────────────┤
│ "IPv6_CMD IPv6_ARG target_ipv6\r\n"     │
│ [Enhanced fuzzed content]               │
└─────────────────────────────────────────┘
```

### Key Differences

| Aspect | IPv4 | IPv6 |
|--------|------|------|
| Header Size | 20 bytes | 40 bytes |
| Address Size | 4 bytes | 16 bytes |
| Checksum | Header + Pseudo-header | Pseudo-header only |
| Fragmentation | Router + Host | Host only |
| Maximum Payload | 65,507 bytes | 65,527 bytes |

## 🔄 Fuzzing Process Flow

### 1. Initialization Phase
```
[Input] -> [IP Validation] -> [Version Detection] -> [Connection Setup]
```

### 2. Connection Establishment
```
IPv4: socket(AF_INET, SOCK_DGRAM/SOCK_STREAM)
IPv6: socket(AF_INET6, SOCK_DGRAM/SOCK_STREAM)
```

### 3. Template Generation
```
[Base Template] -> [Protocol Customization] -> [Size Optimization] -> [Fuzz Points]
```

### 4. Fuzzing Iterations
```
For each mutation:
    [Template] -> [Mutate] -> [Render] -> [Send] -> [Log] -> [Next]
```

### 5. Packet Transmission Sequence

#### UDP Transmission:
1. **Socket Creation**: `socket.socket(AF_INET6, SOCK_DGRAM)`
2. **Binding**: `sock.bind(("::", random_port))`
3. **Connection**: `sock.connect((target_ip, target_port))`
4. **Data Send**: `sock.send(fuzzed_payload)`

#### TCP Transmission:
1. **Socket Creation**: `socket.socket(AF_INET6, SOCK_STREAM)`
2. **Connection**: `sock.connect((target_ip, target_port))`
3. **Handshake**: Three-way TCP handshake
4. **Data Send**: `sock.send(fuzzed_payload)`
5. **Connection Close**: `sock.close()`

## 🎭 Mutation Strategies

### Boofuzz Mutation Types

1. **String Mutations**:
   - Length variations (1 to max_len)
   - Character set variations (ASCII, Unicode, Binary)
   - Format string attacks (%s, %x, %n)
   - Buffer overflow patterns (A*1000, cyclic patterns)

2. **Delimiter Mutations**:
   - Boundary value testing
   - Null byte injection
   - Alternative separators

3. **IPv6-Specific Mutations**:
   - Address compression variations
   - Invalid address formats
   - Zone identifier fuzzing
   - Scope variations

### Example Mutation Progression

**Iteration 1**: `"A \r\n"`
**Iteration 10**: `"AAAAAAAAAA BBBBBBBBBB\r\n"`
**Iteration 50**: `"!@#$%^&*() (){}[]<>\r\n"`
**Iteration 100**: `"A*1024 B*2048 malformed_ipv6\r\n"`
**Iteration 500**: `"\x00\x01\x02...\xFF \x41\x41...\r\n"`

## 📊 Output Files

### Database Files
```
Location: C:/Users/stadmin1.STZUG4/Documents/Jai pentest/
Format: [protocol]_[version]_[unique_id]_fuzz_results.db

Examples:
- udp_ipv6_fdc6_16d7_4e5_f51_fc0_9b40_688a_e9e6_583_1730198432_fuzz_results.db
- tcp_ipv4_192_168_1_100_80_1730198433_fuzz_results.db
```

### HTML Reports
```
Format: [protocol]_[version]_[unique_id]_boofuzz_report.html

Examples:  
- udp_ipv6_f5_156e_942_1_e622_98f1_bb8_64cc_583_1730198432_boofuzz_report.html
- tcp_ipv4_192_168_1_100_80_1730198433_boofuzz_report.html
```

## 🔍 Debugging & Troubleshooting

### Common Issues

#### 1. IPv6 Connection Failures
```
Error: [Errno 99] Cannot assign requested address
Solution: Ensure IPv6 is enabled on your system
Command: ip -6 addr show (Linux) or ipconfig (Windows)
```

#### 2. UDP Binding Issues
```
Error: UDPSocketConnection.recv() requires a bind address/port
Solution: Script automatically handles binding with random ports
```

#### 3. Permission Errors
```
Error: [Errno 1] Operation not permitted  
Solution: Run with administrator/root privileges for raw sockets
```

### Verification Commands

#### Test IPv6 Connectivity
```bash
# Linux/Mac
ping6 fd35:156e:94e2:1:e622:98f1:b8b8:64cc

# Windows  
ping fd35:156e:94e2:1:e622:98f1:b8b8:64cc
```

#### Monitor Network Traffic
```bash
# Wireshark filter for your fuzzing
ipv6.dst == fd35:15e:94e2:1:e622:98f1:8b8:4cc and udp.dstport == 5683

# tcpdump capture
tcpdump -i any "host fd5:156e:94e2:1:e62:9f1:b8b8:64cc and port 5683"
```

## 🎯 Target Analysis

### Identifying Target Services

#### CoAP (Port 5683)
```
Protocol: Constrained Application Protocol
Transport: UDP (primarily)
Payload: Binary CoAP messages
Fuzzing: Text-based payloads test parsing robustness
```

#### HTTP (Port 80)
```
Protocol: Hypertext Transfer Protocol  
Transport: TCP
Payload: "GET / HTTP/1.1\r\nHost: target\r\n\r\n"
Fuzzing: Invalid HTTP tests error handling
```

#### HTTPS (Port 443)
```
Protocol: HTTP over TLS
Transport: TCP with TLS encryption
Payload: TLS handshake required
Fuzzing: Plain text tests TLS parser
```

## 🚀 Advanced Usage Examples

### 1. Comprehensive IPv6 Testing
```bash
# Test multiple protocols on same target
python ipv6_fuzzer.py --ip fd5:56e:94e2:1:e62:981:bb8:4cc --port 5683 --protocol udp --parallel
python ipv6_fuzzer.py --ip fd5:16e:942:1:e62:8f1:bb8:4cc --port 80 --protocol tcp --parallel
python ipv6_fuzzer.py --ip fd5:156e:9e2:1:e62:9f1:bb8:64cc --port 443 --protocol tcp --parallel
```

### 2. Network Range Testing
```bash
# Test multiple targets (requires scripting)
for port in 22 23 53 80 443 993 995 5683; do
    python ipv6_fuzzer.py --ip target::1 --port $port --protocol tcp --parallel &
done
```

### 3. Protocol-Specific Testing
```bash
# CoAP fuzzing with extended timeout
python ipv6_fuzzer.py --ip f5:16e:92:1:e22:8f1:b8:6cc --port 5683 --protocol udp --timeout 30

# SSH fuzzing  
python ipv6_fuzzer.py --ip target::1 --port 22 --protocol tcp --timeout 10
```

## 📈 Performance Optimization

### Resource Management
- **Memory**: Boofuzz caches mutations, monitor RAM usage for large fuzzing campaigns
- **Network**: Rate limiting built into boofuzz prevents overwhelming targets
- **Storage**: Database files grow with iterations, monitor disk space

### Parallel Execution Best Practices
```bash
# Limit concurrent processes to avoid resource exhaustion
max_parallel=5
current_jobs=0

for target in targets.txt; do
    if [ $current_jobs -lt $max_parallel ]; then
        python ipv6_fuzzer.py --ip $target --port 5683 --protocol udp --parallel &
        current_jobs=$((current_jobs + 1))
    else
        wait # Wait for jobs to complete
        current_jobs=0
    fi
done
```

## 🔒 Security Considerations

### Legal & Ethical Use
- **Authorization**: Only test systems you own or have explicit permission to test
- **Documentation**: Maintain clear records of testing scope and authorization
- **Impact**: Monitor target systems for unintended service disruption

### Network Impact
- **Bandwidth**: Fuzzing generates significant network traffic
- **Target Load**: Monitor target system resources during testing
- **Logging**: Fuzzing activities will be logged by target systems

## 📚 References

- [Boofuzz Documentation](https://boofuzz.readthedocs.io/)
- [RFC 8200 - Internet Protocol, Version 6 (IPv6) Specification](https://tools.ietf.org/html/rfc8200)
- [RFC 768 - User Datagram Protocol](https://tools.ietf.org/html/rfc768)
- [RFC 793 - Transmission Control Protocol](https://tools.ietf.org/html/rfc793)
- [RFC 7252 - The Constrained Application Protocol (CoAP)](https://tools.ietf.org/html/rfc7252)

## 🆘 Support

For issues, questions, or contributions:
1. Check the troubleshooting section above
2. Verify network connectivity and permissions
3. Review boofuzz documentation for advanced configuration
4. Monitor target system logs for debugging information

---
**Note**: This tool is designed for authorized security testing only. Ensure you have proper authorization before testing any network targets.

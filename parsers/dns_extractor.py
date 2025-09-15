import struct
import socket
from typing import List, Optional, Dict, Any
from datetime import datetime
import sys
import os

# Add models to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from models.dns_query import DNSQuery

class DNSExtractor:
    """Extract DNS queries from network packets"""
    
    # Ethernet frame constants
    ETHERTYPE_IP = 0x0800
    ETHERTYPE_IPV6 = 0x86DD
    
    # IP protocol constants
    IPPROTO_UDP = 17
    IPPROTO_TCP = 6
    
    # DNS port
    DNS_PORT = 53
    
    def __init__(self):
        self.extracted_queries = []
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'udp_packets': 0,
            'tcp_packets': 0,
            'dns_packets': 0,
            'dns_queries': 0,
            'parse_errors': 0
        }
    
    def extract_dns_from_packet(self, packet: Dict[str, Any]) -> List[DNSQuery]:
        """Extract DNS queries from a single packet"""
        self.stats['total_packets'] += 1
        
        try:
            # Parse Ethernet header (assuming Ethernet link type 1)
            if packet['link_type'] != 1:
                return []
            
            data = packet['data']
            if len(data) < 14:  # Minimum Ethernet header
                return []
            
            # Parse Ethernet header
            eth_header = struct.unpack('!6s6sH', data[:14])
            eth_type = eth_header[2]
            
            if eth_type == self.ETHERTYPE_IP:
                return self._extract_from_ipv4(packet, data[14:])
            elif eth_type == self.ETHERTYPE_IPV6:
                return self._extract_from_ipv6(packet, data[14:])
            
            return []
            
        except Exception as e:
            self.stats['parse_errors'] += 1
            return []
    
    def _extract_from_ipv4(self, packet: Dict[str, Any], ip_data: bytes) -> List[DNSQuery]:
        """Extract DNS from IPv4 packet"""
        if len(ip_data) < 20:  # Minimum IP header
            return []
        
        self.stats['ip_packets'] += 1
        
        # Parse IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_data[:20])
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0x0F) * 4  # Internet Header Length
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        
        if protocol == self.IPPROTO_UDP:
            return self._extract_from_udp(packet, ip_data[ihl:], src_ip, dst_ip)
        elif protocol == self.IPPROTO_TCP:
            return self._extract_from_tcp(packet, ip_data[ihl:], src_ip, dst_ip)
        
        return []
    
    def _extract_from_ipv6(self, packet: Dict[str, Any], ip_data: bytes) -> List[DNSQuery]:
        """Extract DNS from IPv6 packet (simplified)"""
        if len(ip_data) < 40:  # Minimum IPv6 header
            return []
        
        self.stats['ip_packets'] += 1
        
        # Parse IPv6 header (simplified - ignoring extension headers)
        ip_header = struct.unpack('!IHBB16s16s', ip_data[:40])
        next_header = ip_header[2]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_header[4])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_header[5])
        
        if next_header == self.IPPROTO_UDP:
            return self._extract_from_udp(packet, ip_data[40:], src_ip, dst_ip)
        elif next_header == self.IPPROTO_TCP:
            return self._extract_from_tcp(packet, ip_data[40:], src_ip, dst_ip)
        
        return []
    
    def _extract_from_udp(self, packet: Dict[str, Any], udp_data: bytes, src_ip: str, dst_ip: str) -> List[DNSQuery]:
        """Extract DNS from UDP packet"""
        if len(udp_data) < 8:  # Minimum UDP header
            return []
        
        self.stats['udp_packets'] += 1
        
        # Parse UDP header
        udp_header = struct.unpack('!HHHH', udp_data[:8])
        src_port = udp_header[0]
        dst_port = udp_header[1]
        
        # Check if this is DNS traffic
        if src_port == self.DNS_PORT or dst_port == self.DNS_PORT:
            self.stats['dns_packets'] += 1
            return self._parse_dns_message(packet, udp_data[8:], src_ip, dst_ip)
        
        return []
    
    def _extract_from_tcp(self, packet: Dict[str, Any], tcp_data: bytes, src_ip: str, dst_ip: str) -> List[DNSQuery]:
        """Extract DNS from TCP packet (DNS over TCP)"""
        if len(tcp_data) < 20:  # Minimum TCP header
            return []
        
        self.stats['tcp_packets'] += 1
        
        # Parse TCP header
        tcp_header = struct.unpack('!HHLLBBHHH', tcp_data[:20])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        data_offset = (tcp_header[4] >> 4) * 4
        
        # Check if this is DNS traffic
        if src_port == self.DNS_PORT or dst_port == self.DNS_PORT:
            self.stats['dns_packets'] += 1
            # TCP DNS messages are prefixed with 2-byte length
            if len(tcp_data) > data_offset + 2:
                dns_length = struct.unpack('!H', tcp_data[data_offset:data_offset+2])[0]
                dns_data = tcp_data[data_offset+2:data_offset+2+dns_length]
                return self._parse_dns_message(packet, dns_data, src_ip, dst_ip)
        
        return []
    
    def _parse_dns_message(self, packet: Dict[str, Any], dns_data: bytes, src_ip: str, dst_ip: str) -> List[DNSQuery]:
        """Parse DNS message and extract queries"""
        if len(dns_data) < 12:  # Minimum DNS header
            return []
        
        queries = []
        
        try:
            # Parse DNS header
            dns_header = struct.unpack('!HHHHHH', dns_data[:12])
            transaction_id = dns_header[0]
            flags = dns_header[1]
            questions = dns_header[2]
            answers = dns_header[3]
            authority = dns_header[4]
            additional = dns_header[5]
            
            # Check if this is a query (QR bit = 0)
            is_query = (flags & 0x8000) == 0
            
            if is_query and questions > 0:
                # Parse questions section
                offset = 12
                for _ in range(questions):
                    domain, query_type, offset = self._parse_dns_question(dns_data, offset)
                    if domain:
                        query = DNSQuery(
                            domain=domain,
                            timestamp=packet['timestamp'],
                            source_ip=src_ip,
                            query_type=self._get_query_type_name(query_type),
                            destination_ip=dst_ip
                        )
                        queries.append(query)
                        self.stats['dns_queries'] += 1
        
        except Exception:
            self.stats['parse_errors'] += 1
        
        return queries
    
    def _parse_dns_question(self, dns_data: bytes, offset: int) -> tuple:
        """Parse a DNS question and return (domain, query_type, new_offset)"""
        domain = ""
        original_offset = offset
        
        try:
            # Parse domain name
            while offset < len(dns_data):
                length = dns_data[offset]
                offset += 1
                
                if length == 0:
                    break
                elif (length & 0xC0) == 0xC0:
                    # Compression pointer
                    if offset >= len(dns_data):
                        break
                    pointer = ((length & 0x3F) << 8) | dns_data[offset]
                    offset += 1
                    compressed_domain, _, _ = self._parse_dns_question(dns_data, pointer)
                    domain += compressed_domain
                    break
                else:
                    # Regular label
                    if offset + length > len(dns_data):
                        break
                    if domain:
                        domain += "."
                    domain += dns_data[offset:offset+length].decode('utf-8', errors='ignore')
                    offset += length
            
            # Parse query type and class
            if offset + 4 <= len(dns_data):
                query_type, query_class = struct.unpack('!HH', dns_data[offset:offset+4])
                offset += 4
                return domain, query_type, offset
            
        except Exception:
            pass
        
        return None, None, original_offset
    
    def _get_query_type_name(self, query_type: int) -> str:
        """Convert query type number to name"""
        type_names = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV',
            255: 'ANY'
        }
        return type_names.get(query_type, f'TYPE{query_type}')
    
    def get_statistics(self) -> Dict[str, int]:
        """Get extraction statistics"""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset extraction statistics"""
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'udp_packets': 0,
            'tcp_packets': 0,
            'dns_packets': 0,
            'dns_queries': 0,
            'parse_errors': 0
        }
import struct
from datetime import datetime
from typing import Iterator, Dict, Any
import os

class PCAPParser:
    """PCAP file parser for extracting network packets"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.file_handle = None
        self.header_parsed = False
        self.link_type = None
        
    def __enter__(self):
        self.file_handle = open(self.pcap_file, 'rb')
        self._parse_global_header()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_handle:
            self.file_handle.close()
    
    def _parse_global_header(self):
        """Parse PCAP global header"""
        if not self.file_handle:
            raise RuntimeError("File not opened")
            
        header = self.file_handle.read(24)
        if len(header) < 24:
            raise ValueError("Invalid PCAP file - header too short")
        
        # Check magic number to determine endianness
        magic = struct.unpack('I', header[:4])[0]
        if magic == 0xa1b2c3d4:
            # Big endian
            self.endian = '>'
        elif magic == 0xd4c3b2a1:
            # Little endian
            self.endian = '<'
        else:
            raise ValueError(f"Invalid PCAP magic number: {hex(magic)}")
        
        # Parse rest of header
        format_str = f"{self.endian}HHIIII"
        _, _, _, _, _, link_type = struct.unpack(format_str, header[4:])
        self.link_type = link_type
        self.header_parsed = True
    
    def parse_packets(self) -> Iterator[Dict[str, Any]]:
        """Generator that yields parsed packets"""
        if not self.header_parsed:
            raise RuntimeError("Global header not parsed")
        
        packet_count = 0
        while True:
            try:
                packet = self._parse_packet()
                if packet is None:
                    break
                packet['packet_id'] = packet_count
                packet_count += 1
                yield packet
            except struct.error:
                # End of file or corrupted data
                break
    
    def _parse_packet(self) -> Dict[str, Any]:
        """Parse a single packet"""
        if not self.file_handle:
            return None
            
        # Read packet header (16 bytes)
        packet_header = self.file_handle.read(16)
        if len(packet_header) < 16:
            return None
        
        format_str = f"{self.endian}IIII"
        ts_sec, ts_usec, caplen, wirelen = struct.unpack(format_str, packet_header)
        
        # Read packet data
        packet_data = self.file_handle.read(caplen)
        if len(packet_data) < caplen:
            return None
        
        timestamp = datetime.fromtimestamp(ts_sec + ts_usec / 1000000.0)
        
        return {
            'timestamp': timestamp,
            'captured_length': caplen,
            'original_length': wirelen,
            'data': packet_data,
            'link_type': self.link_type
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get basic statistics about the PCAP file"""
        if not os.path.exists(self.pcap_file):
            return {'error': 'File not found'}
        
        file_size = os.path.getsize(self.pcap_file)
        
        # Count packets quickly
        packet_count = 0
        try:
            with self as parser:
                for _ in parser.parse_packets():
                    packet_count += 1
        except Exception as e:
            return {'error': str(e)}
        
        return {
            'file_size': file_size,
            'packet_count': packet_count,
            'link_type': self.link_type
        }
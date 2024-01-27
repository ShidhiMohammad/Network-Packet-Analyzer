# Shidhi Mohammad Bin Arif
# V00911512

import struct
import socket

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   
class Ethernet_Header:
    def __init__(self):
        self.dest_addr = None
        self.src_addr = None
        self.type = None

    def set_dest_addr(self, addr):
        address = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", addr)
        self.dest_addr = address

    def set_src_addr(self, addr):
        address = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", addr)
        self.src_addr = address

    def set_type(self, t):
        type_num = struct.unpack('H', t)[0]
        self.type = type_num

class General_Header:

    def __init__(self):
        self.magic_number = None
        self.version_major = None
        self.version_minor = None
        self.this_zone = None
        self.sigfigs = None
        self.snaplen = None
        self.network = None

    def set_magic_number(self, num):
        self.magic_number = num

    def set_version_major(self, version):
        self.version_major = version

    def set_version_minor(self, version):
        self.version_minor = version

    def set_zone(self, zone):
        self.this_zone = zone

    def set_sigfigs(self, sigfigs):
        self.sigfigs = sigfigs

    def set_snaplen(self, num):
        self.snaplen = num

    def set_network(self, network):
        self.network = network

class Connection:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.address = (src_ip, src_port, dst_ip, dst_port)
        self.packets = []
        src_ip_num = struct.unpack("!I", socket.inet_aton(src_ip))[0]
        dst_ip_num = struct.unpack("!I", socket.inet_aton(dst_ip))[0]
        self.ID = src_ip_num + dst_ip_num + src_port + dst_port
        self.packets_sent = {}
        self.bytes_sent = {}
        self.flags = {"ACK": 0, "RST": 0, "SYN": 0, "FIN": 0}
        self.state = "S0F0"
        self.start_time = float("inf")
        self.end_time = float("-inf")
        self.total_window = 0
        self.min_window = float("inf")
        self.max_window = float("-inf")
        self.rtt_values = []

    def addNewPacket(self, packet):
        self.packets.append(packet)
        self.incrementFlagCounters(packet)
        self.trackPacketsAndBytesSent(packet)
        self.updateConnectionTimes(packet)
        self.updateWindowSizeStats(packet)

    def incrementFlagCounters(self, packet):
        for flag in ["ACK", "RST", "SYN", "FIN"]:
            self.flags[flag] += packet.TCP_header.flags.get(flag, 0)

    def trackPacketsAndBytesSent(self, packet):
        key = packet.IP_header.src_ip
        self.packets_sent[key] = self.packets_sent.get(key, 0) + 1
        self.bytes_sent[key] = self.bytes_sent.get(key, 0) + packet.get_payload()

    def updateConnectionTimes(self, packet):
        if packet.TCP_header.flags["SYN"] == 1 and packet.TCP_header.flags["ACK"] == 0:
            self.start_time = min(packet.timestamp, self.start_time)
        if packet.TCP_header.flags["FIN"] == 1 and packet.TCP_header.flags["ACK"] == 1:
            self.end_time = max(packet.timestamp, self.end_time)

    def updateWindowSizeStats(self, packet):
        self.total_window += packet.TCP_header.window_size
        self.min_window = min(packet.TCP_header.window_size, self.min_window)
        self.max_window = max(packet.TCP_header.window_size, self.max_window)

    def determineConnectionState(self):
        ack = self.flags["ACK"]
        rst = self.flags["RST"]
        syn = self.flags["SYN"]
        fin = self.flags["FIN"]

        self.state = f"S{syn}F{fin}"

        if rst > 0:
            self.state += "/R"
        return self.state

    def computeAllRttValues(self):
        self.rtt_values = []  # Reset the RTT values list

        i = 0
        while i < len(self.packets):
            packet_i = self.packets[i]
            src_ip_i = packet_i.IP_header.src_ip
            tcp_flags_i = packet_i.TCP_header.flags
            payload_len_i = packet_i.get_payload()

            if (
                src_ip_i == self.address[0] and
                not tcp_flags_i.get("RST", 0) and
                (
                    tcp_flags_i.get("SYN", 0) == 1 or
                    tcp_flags_i.get("FIN", 0) == 1 or
                    payload_len_i > 0
                )
            ):
                seq_num_i = packet_i.TCP_header.seq_num
                expected_ack_i = seq_num_i + payload_len_i
                if tcp_flags_i.get("SYN", 0) == 1 or tcp_flags_i.get("FIN", 0) == 1:
                    expected_ack_i += 1  # SYN and FIN consume a sequence number

                j = i + 1
                while j < len(self.packets):
                    packet_j = self.packets[j]
                    dst_ip_j = packet_j.IP_header.src_ip
                    ack_num_j = packet_j.TCP_header.ack_num

                    if dst_ip_j == self.address[2] and ack_num_j == expected_ack_i:
                        rtt = packet_j.timestamp - packet_i.timestamp
                        self.rtt_values.append(round(rtt, 6))
                        break

                    j += 1

            i += 1

        return self.rtt_values


    def isConnectionComplete(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] > 0

    def hasConnectionBeenReset(self):
        return self.flags["RST"] > 0

    def isConnectionStillOpen(self):
        return self.flags["SYN"] > 0 and self.flags["FIN"] == 0

    def calculateConnectionDuration(self):
        if self.end_time == float('-inf'):
            self.end_time = self.packets[-1].timestamp
        return self.start_time, self.end_time, self.end_time - self.start_time

    def countSrcPacketsSent(self):
        return self.packets_sent.get(self.address[0], 0)

    def countDstPacketsSent(self):
        return self.packets_sent.get(self.address[2], 0)

    def countSrcBytesSent(self):
        return self.bytes_sent.get(self.address[0], 0)

    def countDstBytesSent(self):
        return self.bytes_sent.get(self.address[2], 0)

    def totalBytesTransferred(self):
        return self.bytes_sent.get(self.address[0], 0) + self.bytes_sent.get(self.address[2], 0)

    def totalRttPairsCount(self):
        return len(self.rtt_values)

    def totalPacketsCount(self):
        return len(self.packets)

class packet:
    # pcap_hd_info = None
    Ethernet_header = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    size = 0
    incl_len = 0

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.size = 0
        self.incl_len = 16

    def timestamp_set(self, buffer1, buffer2, orig_time, micro):
        seconds = struct.unpack('I', buffer1)[0]
        microseconds = struct.unpack('<I', buffer2)[0]
        time_sec = struct.unpack('I', orig_time)[0]
        time_micro = struct.unpack('<I', micro)[0]
        time = time_sec + time_micro * 0.000001
        self.timestamp = round(seconds + microseconds * 0.000001 - time, 6)
        # print(self.timestamp, self.packet_No)

    def packet_No_set(self, number):
        self.packet_No = number
        # print(self.packet_No)

    def packet_size_set(self, size):
        length = struct.unpack('I', size)[0]
        self.size = length

    def packet_incl_len_set(self, length):
        size = struct.unpack('I', length)[0]
        self.incl_len = size

    def get_payload(self):
        ip_len = self.IP_header.ip_header_len
        ip_total = self.IP_header.total_len
        tcp_offset = self.TCP_header.data_offset
        return ip_total - ip_len - tcp_offset
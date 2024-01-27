# Shidhi Mohammad Bin Arif
# V00911512

import sys
import packet_struct
import socket
import struct

def generatePacketIdentifier(buffer):
    src_ip, src_port, dst_ip, dst_port = buffer
    src_ip_num = struct.unpack("!I", socket.inet_aton(src_ip))[0]
    dst_ip_num = struct.unpack("!I", socket.inet_aton(dst_ip))[0]
    key = src_ip_num + dst_ip_num + src_port + dst_port
    return key

def calculateRoundTripTime(packet, other):
    return round(other.timestamp - packet.timestamp, 8)

def processPacketForConnection(packet, activeConnections):
    ID = generatePacketIdentifier((packet.IP_header.src_ip, packet.TCP_header.src_port, packet.IP_header.dst_ip, packet.TCP_header.dst_port))

    if ID not in activeConnections:
        activeConnections[ID] = packet_struct.Connection(packet.IP_header.src_ip, packet.TCP_header.src_port, packet.IP_header.dst_ip, packet.TCP_header.dst_port)

    activeConnections[ID].addNewPacket(packet)

def parseGeneralHeader(data):
    general_header = packet_struct.General_Header()
    fields = [
        'set_magic_number',
        'set_version_major',
        'set_version_minor',
        'set_zone',
        'set_sigfigs',
        'set_snaplen',
        'set_network'
    ]
    for i, field in enumerate(fields):
        getattr(general_header, field)(data[i*4:(i+1)*4])
    return general_header

def parsePacketHeader(packetSerial, data, time, micro):
    packet = packet_struct.packet()
    (buff1, buff2, incl_len, orig_len) = (data[0:4], data[4:8], data[8:12], data[12:16])

    packet.packet_No_set(packetSerial)
    packet.timestamp_set(buff1, buff2, time, micro)
    packet.packet_incl_len_set(incl_len)
    packet.packet_size_set(orig_len)
    packet.buffer = data

    return packet

def parseEthernetHeader(data):
    header = packet_struct.Ethernet_Header()
    (dest_addr, src_addr, type_field) = (data[0:6], data[6:12], data[12:14])

    header.set_dest_addr(dest_addr)
    header.set_src_addr(src_addr)
    header.set_type(type_field)

    return header

def parseIpHeader(data):
    header = packet_struct.IP_Header()

    src_ip = data[26:30]
    dest_ip = data[30:34]
    total_length = data[16:18]
    header_length = data[14:15]

    header.get_IP(src_ip, dest_ip)
    header.get_total_len(total_length)
    header.get_header_len(header_length)
    
    return header

def parseTcpHeader(data):
    tcp_header = packet_struct.TCP_Header()

    src_port = data[34:36]
    dest_port = data[36:38]
    seq_num = data[38:42]
    ack_num = data[42:46]
    data_offset = data[46:47]
    flags = data[47:48]
    window_size_part1 = data[48:49]
    window_size_part2 = data[49:50]

    tcp_header.get_src_port(src_port)
    tcp_header.get_dst_port(dest_port)
    tcp_header.get_seq_num(seq_num)
    tcp_header.get_ack_num(ack_num)
    tcp_header.get_data_offset(data_offset)
    tcp_header.get_window_size(window_size_part1, window_size_part2)
    tcp_header.get_flags(flags)

    return tcp_header

def summarizeStatistics(activeConnections):
    statistics = {
        "complete": 0,
        "reset": 0,
        "open": 0,
        "total_packets": 0,
        "min_time": float('inf'),
        "mean_time": 0,
        "max_time": float('-inf'),
        "min_packets": float('inf'),
        "mean_packets": 0,
        "max_packets": float('-inf'),
        "min_rtt": float('inf'),
        "mean_rtt": 0,
        "max_rtt": float('-inf'),
        "total_rtt": 0,
        "min_window": float('inf'),
        "mean_window": 0,
        "max_window": float('-inf'),
    }

    for conn in activeConnections.values():
        start_time, end_time, total_time = conn.calculateConnectionDuration()
        if conn.isConnectionComplete():
            statistics["complete"] += 1
            total_packets = conn.totalPacketsCount()
            statistics["total_packets"] += total_packets
            statistics["min_time"] = min(total_time, statistics["min_time"])
            statistics["mean_time"] += total_time
            statistics["max_time"] = max(total_time, statistics["max_time"])
            statistics["min_packets"] = min(total_packets, statistics["min_packets"])
            statistics["mean_packets"] += total_packets
            statistics["max_packets"] = max(total_packets, statistics["max_packets"])
            rtt_values = conn.computeAllRttValues()
            statistics["min_rtt"] = min(min(rtt_values), statistics["min_rtt"])
            statistics["mean_rtt"] += sum(rtt_values)
            statistics["max_rtt"] = max(max(rtt_values), statistics["max_rtt"])
            statistics["total_rtt"] += conn.totalRttPairsCount()
            statistics["min_window"] = min(conn.min_window, statistics["min_window"])
            statistics["mean_window"] += conn.total_window
            statistics["max_window"] = max(conn.max_window, statistics["max_window"])
        if conn.hasConnectionBeenReset():
            statistics["reset"] += 1
        if conn.isConnectionStillOpen():
            statistics["open"] += 1
    return statistics

def printConnectionDetails(conn, connNumber):
    print(f"Connection: {connNumber}")
    print(f"Source Address: {conn.address[0]}")
    print(f"Source Port: {conn.address[1]}")
    print(f"Destination Address: {conn.address[2]}")
    print(f"Destination Port: {conn.address[3]}")
    print(f"Status: {conn.determineConnectionState()}")
    if conn.isConnectionComplete():
        start_time, end_time, total_time = conn.calculateConnectionDuration()
        print(f"Start Time: {start_time} seconds")
        print(f"End Time: {end_time} seconds")
        print(f"Duration: {round(total_time, 6)} seconds")
        print(f"Number of packets sent from Source to Destination: {conn.countSrcPacketsSent()}")
        print(f"Number of packets sent from Destination to Source: {conn.countDstPacketsSent()}")
        print(f"Total number of packets: {conn.totalPacketsCount()}")
        print(f"Number of data bytes sent from Source to Destination: {conn.countSrcBytesSent()}")
        print(f"Number of data bytes sent from Destination to Source: {conn.countDstBytesSent()}")
        print(f"Total number of bytes sent: {conn.totalBytesTransferred()}") 
        print("END")
    print("++++++++++++++++++++++++++++++++")

def summarizeConnectionDetails(activeConnections):
    statistics = summarizeStatistics(activeConnections)
    
    print("Output For Assignment 2: \n")
    print(f"A) Total Number of connections: {len(activeConnections)}")
    print("------------------------")
    print("B) Connection Details:")
    for inc, conn in enumerate(activeConnections.values(), 1):
        printConnectionDetails(conn, inc)
        
    print("-----------------------------------------------")
    print("C) GENERAL\n")
    print(f"Total number of complete TCP connections: {statistics['complete']}")
    print(f"Number of reset TCP connections: {statistics['reset']}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {statistics['open']}")
    print("--------------------------------------------------")
    print("D) Complete TCP connections:\n")
    complete_connections = statistics['complete'] if statistics['complete'] > 0 else 1  # Avoid division by zero
    print(f"Minimum time duration: {statistics['min_time']:.6f} seconds")
    print(f"Mean time duration: {statistics['mean_time'] / complete_connections:.6f} seconds")
    print(f"Maximum time duration: {statistics['max_time']:.6f} seconds")
    print()
    if statistics['total_rtt'] > 0:  # Avoid division by zero
        print(f"Minimum RTT value: {statistics['min_rtt']:.6f}")
        print(f"Mean RTT value: {statistics['mean_rtt'] / statistics['total_rtt']:.6f}")
        print(f"Maximum RTT value: {statistics['max_rtt']:.6f}")
    else:
        print("No RTT values to calculate.")
    print()
    print(f"Minimum number of packets including both send/received: {statistics['min_packets']}")
    print(f"Mean number of packets including both send/received: {statistics['mean_packets'] / complete_connections:.4f}")
    print(f"Maximum number of packets including both send/received: {statistics['max_packets']}")
    print()
    total_windows = statistics['total_packets'] if statistics['total_packets'] > 0 else 1  # Avoid division by zero
    print(f"Minimum receive window size including both send/received: {statistics['min_window']} bytes")
    print(f"Mean receive window size including both send/received: {statistics['mean_window'] / total_windows:.6f} bytes")
    print(f"Maximum receive window size including both send/received: {statistics['max_window']} bytes")
    print("--------------------------------------------------")


def main():
    file_name = sys.argv[1]

    capturedPackets = []
    activeConnections = {}
    packetSerial = 0

    with open(file_name, "rb") as file:
        rawData = file.read(24)
        parseGeneralHeader(rawData)

        rawData = file.read(16)
        initialTimestampSec = rawData[0:4]
        initialTimestampMicrosec = rawData[4:8]
        capturedPackets.append(parsePacketHeader(packetSerial, rawData, initialTimestampSec, initialTimestampMicrosec))

        rawData = file.read(capturedPackets[packetSerial].incl_len)
        capturedPackets[packetSerial].Ethernet_header = parseEthernetHeader(rawData)
        capturedPackets[packetSerial].IP_header = parseIpHeader(rawData)
        capturedPackets[packetSerial].TCP_header = parseTcpHeader(rawData)
        processPacketForConnection(capturedPackets[packetSerial], activeConnections)

        while True:
            try:
                rawData = file.read(16)
                if not rawData:
                    break
                packetSerial += 1
                capturedPackets.append(parsePacketHeader(packetSerial, rawData, initialTimestampSec, initialTimestampMicrosec))

                rawData = file.read(capturedPackets[packetSerial].incl_len)
                capturedPackets[packetSerial].Ethernet_header = parseEthernetHeader(rawData)
                capturedPackets[packetSerial].IP_header = parseIpHeader(rawData)
                capturedPackets[packetSerial].TCP_header = parseTcpHeader(rawData)
                processPacketForConnection(capturedPackets[packetSerial], activeConnections)
            except struct.error:
                break

    summarizeConnectionDetails(activeConnections)

if __name__ == "__main__":
    main()
# encoding=utf-8
import csv
import datetime
import os
import random
import socket

import dpkt
import numpy as np
from dpkt.compat import compat_ord
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier

# from keras.preprocessing import sequence
# from keras.models import Sequential
# from keras.layers import Dense, Dropout, Activation
# from keras.layers import Embedding
# from keras.layers import Conv1D, GlobalMaxPooling1D, MaxPooling1D, GlobalAveragePooling1D
# import keras


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def parse_data(udp_data):
    """Conver data in UDP to readable string

       Args:
           udp_data: hex form
       Returns:
           str:
    """

    return ' '.join('%02x' % compat_ord(b) for b in udp_data)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def parse_packets(pcap):
    """Parse useful information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    flow_Info = []
    times = 0
    for timestamp, buf in pcap:
        times += 1
        tmp_flow_Info = {}

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # Unpack the data whthin the Ethernet frame (the IP packet)
        ip = eth.data

        # if protocol(ip.p) is not UDP(17) ,skip this packet
        if ip.p != 17:
            continue

        udp = ip.data
        # Temp_data = parse_data(eth.data.udp.data)
        # Filter CoAP by port
        if(udp.sport != 5683 or udp.dport != 5683):
            continue

        str_udp_data = parse_data(eth.data.udp.data)
        # skip packets of Non_confirmable
        if str_udp_data[0] == '5': 
            continue

        cycle = 0
        index = 0
        Udp_data = []
        
        len_str_udp_data = len(str_udp_data)
        while cycle < (len_str_udp_data//3+1):
            # Udp_data.append(int('0x'+Str_Udp_data[index:index + 2], 16))
            Udp_data.append(int('0x' + str_udp_data[index:index + 2], 16))
            cycle += 1
            index += 3
        tmp_flow_Info['udp_data'] = (Udp_data)

        # confirmable or ack
        tmp_flow_Info['Coap_type'] = str_udp_data[0]
        #print(str_udp_data)  
        
        # skip space and get "Message ID"        
        HexMide = str_udp_data[6:8] + str_udp_data[9:11]
        tmp_flow_Info['Mid'] = int('0x'+HexMide, 16)

        tmp_flow_Info['Timestamp'] = str(datetime.datetime.fromtimestamp(timestamp))
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        tmp_flow_Info['src'] = inet_to_str(ip.src)
        tmp_flow_Info['dst'] = inet_to_str(ip.dst)

        tmp_flow_Info['sport'] = udp.sport
        tmp_flow_Info['dport'] = udp.dport
        flow_Info.append(tmp_flow_Info)

    return flow_Info


def parseflow(flow_parse, Current_flow, maxlen):
    src = Current_flow['src']
    dst = Current_flow['dst']
    Mid = Current_flow['Mid']
    # len_flow_parse = len(flow_parse)
    ExitFlag = 0
   
    for flow in flow_parse:
        if ('src' in flow) and ((flow['src'] in src) and (flow['dst'] in dst) and (flow['Mid'] == Mid)):
            ExitFlag = 1
            break
        if ('src' in flow) and ((flow['src'] in dst) and (flow['dst'] in src) and (flow['Mid'] == Mid)):
            ExitFlag = 1
            break

    if (ExitFlag == 0):
        tmp_flow_Info = {}
        # if "Coap_type" is 4, it shows this packet is "Comformable"
        if Current_flow['Coap_type'] == '4':
            tmp_flow_Info['udp_data'] = Current_flow['udp_data']
            tmp_flow_Info['Start_time'] = Current_flow['Timestamp']
            tmp_flow_Info['src'] = Current_flow['src']
            tmp_flow_Info['dst'] = Current_flow['dst']
            tmp_flow_Info['Mid'] = Current_flow['Mid']
            if Current_flow['udp_data'][-3:] == [170, 70, 0]: # OFF
                tmp_flow_Info['use_type'] = 0
            elif Current_flow['udp_data'][-3:] == [170, 70, 1]:# ON
                tmp_flow_Info['use_type'] = 1
            elif Current_flow['udp_data'][-3:] == [170, 68, 1]: #  adjust
                tmp_flow_Info['use_type'] = 2
            elif Current_flow['udp_data'][-3:] == [255, 170, 255]:  # upload
                tmp_flow_Info['use_type'] = 3
            else:
                tmp_flow_Info['use_type'] = 4  # failure
        # if "Coap_type" is 6, it shows this packet is "AckComformable"
        if Current_flow['Coap_type'] == '6':
            tmp_flow_Info['End_time'] = Current_flow['Timestamp']
            tmp_flow_Info['src'] = Current_flow['dst']
            tmp_flow_Info['dst'] = Current_flow['src']
            tmp_flow_Info['Mid'] = Current_flow['Mid']
        # if "tmp_flow_info" is not null, add this flow into list("flow_parse")
        if tmp_flow_Info != {}:
            flow_parse.append(tmp_flow_Info)
        else:
            print(Current_flow)

        if len(Current_flow['udp_data']) > maxlen:
            maxlen = len(Current_flow['udp_data'])

    if (ExitFlag == 1):
        if Current_flow['Coap_type'] == '4':
            flow['udp_data'] = Current_flow['udp_data']
            flow['Start_time'] = Current_flow['Timestamp']
        if Current_flow['Coap_type'] == '6':
            flow['End_time'] = Current_flow['Timestamp']

    return maxlen


if __name__ == '__main__':

    cap_files_list = []
    print(os.getcwd())
    for root, dirs, files in os.walk(os.path.join(os.getcwd(), 'data', 'raw')):
        for file in files:
            if os.path.splitext(file)[-1] == '.cap':
                cap_files_list.append(os.path.join(root, file))
        break

    flow_Info = []
    for file in cap_files_list:
        with open(file, 'rb') as f:
            pacp = dpkt.pcap.Reader(f)
            Temp_flow_Info = parse_packets(pacp)
            flow_Info += Temp_flow_Info
    #print(len(flow_Info))

    flow_parse = []
    maxlen = 0
    for flow in flow_Info:
        Current_flow = flow
        maxlen = parseflow(flow_parse, Current_flow, maxlen)
        
    print(maxlen)

    for flow in flow_parse:
        if len(flow['udp_data']) < maxlen:
            difflen = maxlen - len(flow['udp_data'])
            flow['udp_data'] = [[0]*difflen][0] + flow['udp_data']
            # flow['udp_data'] = flow['udp_data'] + [[0]*difflen][0]
    with open('./data/interim/data_handle.csv', 'w+', newline='') as fs:
        csvStat = csv.writer(fs)
        csvStat.writerow(flow_parse[0].keys())
        for flow in flow_parse:
            csvStat.writerow(flow.values())


# Machine Learning

    # X_data = [x['udp_data'] for x in flow_parse]
    # Y_data = [x['use_type'] for x in flow_parse]
    # while sum([x == 3 for x in Y_data]) > 60:
    #     idx_3 = Y_data.index(3)
    #     del Y_data[idx_3]
    #     del X_data[idx_3]
    # while sum([x == 4 for x in Y_data]):
    #     idx_4 = Y_data.index(4)
    #     del Y_data[idx_4]
    #     del X_data[idx_4]

    # seque = np.arange(len(Y_data))
    # temp = [i for i in np.arange(len(Y_data))]
    # random.shuffle(seque)
    # X1_shuffle = (np.array(X_data)[seque])/255
    # Y1_shuffle = (np.array(Y_data)[seque])
    # lenall = len(X_data)
    # lentrain = lenall//4 * 3
    # X_In_Train = X1_shuffle[0:lentrain]
    # Y_In_Train = Y1_shuffle[0:lentrain]
    # X_In_Test = X1_shuffle[lentrain:]
    # Y_In_Test = Y1_shuffle[lentrain:]
    # rf1 = RandomForestClassifier(n_estimators=100, max_depth=4).fit(X_In_Train, Y_In_Train)
    # Y_results = rf1.predict(X_In_Test)
    # ACCURACY= metrics.accuracy_score(Y_results, Y_In_Test)
    # print('ACCURACY is %f', ACCURACY)
    # S = 1

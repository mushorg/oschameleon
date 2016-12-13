# Copyright (c) 2015 Lukas Rist

import random

from stack_packet.template import OSPatternTemplate

'''
TODO
ISR
TS   not correct
SS
S
A
U1  IE   R
T

''' 



def _str2int(string):
    try:
        return int(string)
    except ValueError:
        return int('0x' + string, 16)


def _parse_range(value, step=5):
    if '-' in value:
        return map(_str2int, value.split('-'))
    else:
        return _str2int(value), _str2int(value) + step


def _switch(a, b):
    tmp = a
    a = b
    b = tmp

    return a, b

def _upper_end_hex(string, start):
    for i in range(start, len(string)):
        try:
            int(string[i],16)
        except ValueError, e:
            return i


# timestamp
def set_ip_timestamp(os_pattern, fp):

    ts = fp['SEQ']['TS']
    ts_ans = 0

    if ts == 'U':
        ts_ans = 1

    elif ts == '0':
        ts_ans = 0

    elif ts == '1':
        ts_ans = random.randint(0,5)

    elif ts == '7':
        ts_ans = random.randint(70,150)

    elif ts == '8':
        ts_ans = random.randint(150,350)

    else:
        # round(log2(average increments per second)) = A
        ts_ans = 2048

    print ts_ans

    os_pattern.TCP_TS_CNT = ts_ans

    return os_pattern


# probes to send
def set_probes_to_send(os_pattern, fp):

    for c in fp.keys():
        ans = 1 

        if 'R' in fp[c].keys():
            if fp[c]['R'] == 'N':
                ans = 0

        if c in os_pattern.PROBES_2_SEND.keys():
            os_pattern.PROBES_2_SEND[c] = ans

        elif c == 'T1':
            os_pattern.PROBES_2_SEND['P1'] = ans
            os_pattern.PROBES_2_SEND['P2'] = ans
            os_pattern.PROBES_2_SEND['P3'] = ans
            os_pattern.PROBES_2_SEND['P4'] = ans
            os_pattern.PROBES_2_SEND['P5'] = ans
            os_pattern.PROBES_2_SEND['P6'] = ans

    

    # if no WIN and OPS probe test,  set to 0
    ans = 1
    if 'R' in fp['OPS'].keys() and 'R' in fp['WIN'].keys():
        if fp['OPS']['R'] == 'N' and fp['WIN']['R'] == 'N':
            ans = 0

    os_pattern.PROBES_2_SEND['P5'] = ans
    os_pattern.PROBES_2_SEND['P6'] = ans

    return os_pattern


# Dont fragment
def set_ip_fragment_flag(os_pattern, fp):

    # set the ip fragment flag
    for c in fp.keys():
        if 'DF' in fp[c].keys():

            ans = 0
            if fp[c]['DF'] == 'Y':
                ans = 1

            if c in os_pattern.TCP_OPTIONS.keys():

                if c == 'T1':
                    os_pattern.TCP_OPTIONS['P1']['DF'] = ans
                    os_pattern.TCP_OPTIONS['P2']['DF'] = ans
                    os_pattern.TCP_OPTIONS['P3']['DF'] = ans
                    os_pattern.TCP_OPTIONS['P4']['DF'] = ans
                    os_pattern.TCP_OPTIONS['P5']['DF'] = ans
                    os_pattern.TCP_OPTIONS['P6']['DF'] = ans
                else:
                    os_pattern.TCP_OPTIONS[c]['DF'] = ans

        if 'DFI' in fp[c].keys():
            ans = 0

            if fp[c]['DFI'] == 'Y':
                ans = 1

            os_pattern.TCP_OPTIONS[c]['DF'] = ans

    return os_pattern


# split the tcp options
def split_tcp_option(value):
    
    current_probe = []
    timestamp = []

    for ch in range(len(value)):
        ans = 0

        # MSS
        if value[ch] == 'M':
            upper = _upper_end_hex(value, ch+1)
            ans = value[ch+1:upper]
            #int('0x' + string, 16)
            ans = int('0x' + ans, 16)
            current_probe.append(('MSS', ans))

        # NOP
        if value[ch] == 'N':
            current_probe.append(('NOP', 0))

        # EOL
        if value[ch] == 'L':
            current_probe.append(('EOL',0))

        # Window size
        if value[ch] == 'W':
            upper = _upper_end_hex(value, ch+1)
            ans = value[ch+1:upper]
            current_probe.append(('WScale', ans))

        # Timestamp
        if value[ch] == 'T':
            ans =  value[ch+1:ch+3]
            tsval = value[ch+1:ch+2]
            tsver = value[ch+2:ch+3]
            #timestamp.append(('Timestamp', (str(tsval+tsver))))
            timestamp.append(tsval)
            timestamp.append(tsver)

        # selective ack permitted
        if value[ch] == 'S':
            current_probe.append(('SAckOK', ''))

    return current_probe, timestamp


# TCP Options
def set_tcp_option(os_pattern, fp):
    # set tcp options
    # python: options=[('Experiment', (0xf989, 0xcafe, 0x0102, 0x0002)), ('NOP', 0), ('NOP', 0)])
    # pkt[TCP].options
    # M5B4NNT11
    if 'O1' in fp['OPS'].keys():
        for current_option in fp['OPS']:
            # get the number of the probe O1, O2
            current = current_option[1]

            # the value in the template
            value = fp['OPS'][current_option];
            
            # 
            current_probe, timestamp = split_tcp_option(value)

            # set value in os_pattern
            os_pattern.TCP_OPTIONS['P'+current]['O'] = current_probe

            if timestamp:
                os_pattern.TCP_Timestamp['P'+current]['tsval'] = timestamp[0]
                os_pattern.TCP_Timestamp['P'+current]['tsver'] = timestamp[1]
                #os_pattern.TCP_Timestamp['P'+current] = timestamp

            #os_pattern.TCP_OPTIONS['P'+current]['O'] = os_pattern.TCP_OPTIONS['P'+current]['O'] + os_pattern.TCP_Timestamp['P'+current]

    # T2-7
    for c in fp.keys():
        if 'O' in fp[c].keys():
            if fp[c]['O'] != '':

                # the value in the template
                value = fp[c]['O']

                current_probe, timestamp = split_tcp_option(value)

                os_pattern.TCP_OPTIONS[c]['O'] = current_probe

                os_pattern.TCP_Timestamp[c] = []

                if timestamp:
                    os_pattern.TCP_Timestamp[c]['tsval'] = timestamp[0]
                    os_pattern.TCP_Timestamp[c]['tsver'] = timestamp[1]
                    #os_pattern.TCP_Timestamp[c] = timestamp

                #os_pattern.TCP_OPTIONS[c]['O'] = os_pattern.TCP_OPTIONS[c]['O'] + os_pattern.TCP_Timestamp[c]

    return os_pattern


def set_win_option(os_pattern, fp):
    # set window size for 
    if 'W1' in fp['WIN'].keys():
        os_pattern.TCP_OPTIONS['P1']['W'] = int(fp['WIN']['W1'], 16)
        os_pattern.TCP_OPTIONS['P2']['W'] = int(fp['WIN']['W2'], 16)
        os_pattern.TCP_OPTIONS['P3']['W'] = int(fp['WIN']['W3'], 16)
        os_pattern.TCP_OPTIONS['P4']['W'] = int(fp['WIN']['W4'], 16)
        os_pattern.TCP_OPTIONS['P5']['W'] = int(fp['WIN']['W5'], 16)
        os_pattern.TCP_OPTIONS['P6']['W'] = int(fp['WIN']['W6'], 16)


    for c in fp.keys():
        if 'W' in fp[c].keys():
            if c in os_pattern.TCP_OPTIONS.keys():
                os_pattern.TCP_OPTIONS[c]['W'] = int(fp[c]['W'], 16)

    return os_pattern


# CI
def set_ci(os_pattern, fp):

    for c in fp.keys():
        # nmap probe for windows does not contain CI key
        if 'CI' in fp[c].keys():
            os_pattern.IP_ID_CI_CNT = fp['SEQ']['CI']
            break;

    return os_pattern


# TTL
def set_tcp_ttl(os_pattern,fp):
    # todo
    for c in fp.keys():
        if 'T' in fp[c].keys():
            # the value was added in get_os_pattern()
            # if the T key is not in the template, add the 
            # TG value

            os_pattern.TTL = int(fp[c]['T'])

            # d = _str2int(fp['T1']['TG'])
            #os_pattern.TTL = int((fp[c]['T']),16)
            #os_pattern.TTL = _str2int(hex(d).split('x')[1])
            #os_pattern.TTL = chr(_str2int(fp['T1']['TG']))
            #os_pattern.TTL = int(fp['T1']['TG'],10)
            break;
        elif 'TG' in fp[c].keys():
            os_pattern.TTL = int((fp[c]['TG']),16)
            break;

    return os_pattern


def get_os_pattern(fprint_template):
    os_pattern = OSPatternTemplate()
    #print os_pattern.TTL
    with open(fprint_template, 'rb') as fh:
        data = fh.readlines()

    fp = dict()
    fp.clear()

    for line in data:
        line = line.strip()
        category, result = line.split('(', 1)
        result = result[:-1]
        fp[category] = dict()
        for item in result.split('%'):
            key, val = item.split('=')
            if '|' in val:
                # eg. GCD=FA7F|1F4FE|2EF7D|3E9FC|4E47B
                val = random.choice(val.split('|'))
            if '-' in val:
                minVal,maxVal = val.split('-')

                # choose random number in the range min-max
                # eg. SP=0-5
                # os_pattern.SP_MIN, os_pattern.SP_MAX = _parse_range(fp['SEQ']['SP'])
                if key == 'SP':
                    minVal = _str2int(minVal)
                    maxVal = _str2int(maxVal)
                    if minVal > maxVal:
                        minVal, maxVal = _switch(minVal, maxVal)
                    os_pattern.SP_MIN = minVal
                    os_pattern.SP_MAX = maxVal
                    val = str(random.randint(minVal,maxVal))

                #
                if key == 'GCD':
                    minVal = _str2int(minVal)
                    maxVal = _str2int(maxVal)
                    if minVal > maxVal:
                        minVal, maxVal = _switch(minVal, maxVal)
                    val = str(random.randint(minVal,maxVal))
                    
                # 
                if key == 'ISR':
                    os_pattern.ISR_MIN = _str2int(minVal)
                    os_pattern.ISR_MAX = _str2int(maxVal)

                if key == 'T':
                    minD = int(minVal, 16)
                    maxD = int(maxVal, 16)
                    val = str(random.randint(minD, maxD))


            # print "category " + category + "    key "+ key + "   val "+val
            fp[category][key] = val

    # GCD
    os_pattern.GCD = _str2int(fp['SEQ']['GCD'])

    # TI
    os_pattern.IP_ID_TI_CNT = fp['SEQ']['TI']

    # CI
    os_pattern = set_ci(os_pattern, fp)

    # II
    os_pattern.IP_ID_TI_CNT = fp['SEQ']['II']

    # set time to live
    os_pattern = set_tcp_ttl(os_pattern,fp)

    # TS timestamp 
    os_pattern = set_ip_timestamp(os_pattern,fp)

    # R  set the PROBES_2_SEND flags 
    os_pattern = set_probes_to_send(os_pattern, fp)

    # DF  fragment flag 
    os_pattern = set_ip_fragment_flag(os_pattern,fp)
    
    # set OPS tcp option
    # tcp options
    os_pattern = set_tcp_option(os_pattern,fp)

    # set WIN and window option
    # window size 
    os_pattern = set_win_option(os_pattern, fp)

    return os_pattern

if __name__ == '__main__':
    print get_os_pattern('SIMATIC_300_PLC.txt')
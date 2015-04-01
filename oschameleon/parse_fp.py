# Copyright (c) 2015 Lukas Rist

import osfuscation
from pprint import pprint
import random


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


def get_os_pattern(fprint_template):
    os_pattern = osfuscation.OSPatternTemplate()

    with open(fprint_template, 'rb') as fh:
        data = fh.readlines()

    fp = dict()

    for line in data:
        line = line.strip()
        category, result = line.split('(', 1)
        result = result[:-1]
        fp[category] = dict()
        for item in result.split('%'):
            key, val = item.split('=')
            if '|' in val:
                val = random.choice(val.split('|'))
            fp[category][key] = val

    os_pattern.GCD = _str2int(fp['SEQ']['GCD'])
    os_pattern.SP_MIN, os_pattern.SP_MAX = _parse_range(fp['SEQ']['SP'])
    os_pattern.ISR_MIN, os_pattern.ISR_MAX = _parse_range(fp['SEQ']['ISR'])
    os_pattern.IP_ID_TI_CNT = fp['SEQ']['TI']
    os_pattern.IP_ID_CI_CNT = fp['SEQ']['CI']
    os_pattern.IP_ID_TI_CNT = fp['SEQ']['II']

    return os_pattern


if __name__ == '__main__':
    print get_os_pattern('SIMATIC_300_PLC.txt')

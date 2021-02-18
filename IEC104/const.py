TYPEID_ASDU = {
    0x01: 'M_SP_NA_1 (1)',
    0x03: 'M_DP_NA_1 (3)',
    0x05: 'M_ST_NA_1 (5)',
    0x07: 'M_BO_NA_1 (7)',
    0x09: 'M_ME_NA_1 (9)',
    0x0D: 'M_ME_NC_1 (13)',
    0x1E: 'M_SP_TB_1 (30)',
    0x1F: 'M_DP_TB_1 (31)',
    0x24: 'M_ME_TF_1 (36)',
    0x25: 'M_IT_TB_1 (37)',
    0x2D: 'C_SC_NA_1 (45)',
    0x2E: 'C_DC_NA_1 (46)',
    0x32: 'C_SE_NC_1 (50)',
    0x46: 'M_EI_NA_1 (70)',
    0x64: 'C_IC_NA_1 (100)',
    0x67: 'C_CS_NA_1 (103)',
}

TYPE_APCI = {
    0x00: 'I (0x00)',
    0x01: 'S (0x01)',
    0x03: 'U (0x03)'
}

UNNUMBERED_CONTROL_FIELD = {
    0x01: 'STARTDT act',
    0x02: 'STARTDT con',
    0x04: 'STOPDT act',
    0x08: 'STOPDT con',
    0x10: 'TESTFR act',
    0x20: 'TESTFR con',
}

CAUSE_OF_TX = {
    0: 'not used',
    1: 'per/cyc',
    2: 'back',
    3: 'spont',
    4: 'init',
    5: 'req',
    6: 'act',
    7: 'ActCon',
    8: 'deact',
    9: 'DeactCon',
    10: 'ActTerm',
    11: 'retrem',
    12: 'retloc',
    13: 'file',
    20: 'inrogen',
    21: 'inro1',
    22: 'inro2',
    23: 'inro3',
    24: 'inro4',
    25: 'inro5',
    26: 'inro6',
    27: 'inro7',
    28: 'inro8',
    29: 'inro9',
    30: 'inro10',
    31: 'inro11',
    32: 'inro12',
    33: 'inro13',
    34: 'inro14',
    35: 'inro15',
    36: 'inro16',
    37: 'reqcogen',
    38: 'reqco1',
    39: 'reqco2',
    40: 'reqco3',
    41: 'reqco4',
    44: 'unknown type identification',
    45: 'unknown cause of transmission',
    46: 'unknown common address of ASDU',
    47: 'unknown information object address'
}

QDS_FLAGS = ['OV', '*', '*', '*', 'BL', 'SB', 'NT', 'IV']

DIQ_FLAGS = ['*', '*', '*', '*', 'BL', 'SB', 'NT', 'IV']

SIQ_FLAGS = ['SPI', '*', '*', '*', 'BL', 'SB', 'NT', 'IV']

SQ_ENUM = {
    0X00: False,
    0x80: True
}

SU = {
    0X80: 'summer time',
    0x00: 'normal time'
}

#Day Of Week
DOW_ENUM = {
    0x00: 'undefined',
    0x01: 'monday',
    0x02: 'tuesday',
    0x03: 'wednesday',
    0x04: 'thursday',
    0x05: 'friday',
    0x06: 'saturday',
    0x07: 'sunday'
}

SEL_EXEC = {
    0x00: 'Execute',
    0x80: 'Select',
    0x01: 'Select',
}

DPI_ENUM = {
    0x00: 'Indeterminate or Intermediate state',
    0x01: 'Determined state OFF',
    0x02: 'Determined state ON',
    0x03: 'Indeterminate state'
}

TRANSIENT = {
    0x00: 'not in transient',
    0x80: 'in transient'
}

QOI_ENUM = {
    0x14: 'Station interrogation (global)',
    0x15: 'Interrogation of group 1',
    0x16: 'Interrogation of group 2',
    0x17: 'Interrogation of group 3',
    0x18: 'Interrogation of group 4',
    0x19: 'Interrogation of group 5',
    0x1A: 'Interrogation of group 6',
    0x1B: 'Interrogation of group 7',
    0x1C: 'Interrogation of group 8',
    0x1D: 'Interrogation of group 9',
    0x1E: 'Interrogation of group 10',
    0x1F: 'Interrogation of group 11',
    0x20: 'Interrogation of group 12',
    0x21: 'Interrogation of group 13',
    0x22: 'Interrogation of group 14',
    0x23: 'Interrogation of group 15',
    0x24: 'Interrogation of group 16'
}


R_ENUM = {
    0x00: 'Local power switch on',
    0x01: 'Local manual reset',
    0x02: 'Remote reset',
}
for i in range(0x03, 0x7f):
    R_ENUM[i] = 'Undefined'

I_ENUM = {
    0x00: 'Initialization with unchanged local parameters',
    0x80: 'Initialization after change of local parameters'
}

QU_ENUM = {
    0x00: 'no pulse defined',
    0x01: 'short pulse duration (circuit-breaker)',
    0x02: 'long pulse duration',
    0x03: 'persistent output',
    0x04: 'reserved',
    0x05: 'reserved',
    0x06: 'reserved',
}

SCS_ENUM = {
    0x00: 'OFF',
    0x01: 'ON'
}

PN_ENUM = {
    0x00: 'Positive confirm',
    0x40: 'Negative confirm'
}
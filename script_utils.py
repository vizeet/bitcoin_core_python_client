import os
import json
import binascii
from opcode_declarations import *

g_opcode_value_dict = {
        "OP_FALSE": OP_FALSE,
        "OP_0": OP_0,
        "OP_PUSHDATA1": OP_PUSHDATA1,
        "OP_PUSHDATA2": OP_PUSHDATA2,
        "OP_PUSHDATA4": OP_PUSHDATA4,
        "OP_1NEGATE": OP_1NEGATE,
        "OP_1": OP_1,
        "OP_TRUE": OP_TRUE,
        "OP_2": OP_2,
        "OP_3": OP_3,
        "OP_4": OP_4,
        "OP_5": OP_5,
        "OP_6": OP_6,
        "OP_7": OP_7,
        "OP_8": OP_8,
        "OP_9": OP_9,
        "OP_10": OP_10,
        "OP_11": OP_11,
        "OP_12": OP_12,
        "OP_13": OP_13,
        "OP_14": OP_14,
        "OP_15": OP_15,
        "OP_16": OP_16,
        "OP_NOP": OP_NOP,
        "OP_IF": OP_IF,
        "OP_VERIFY": OP_VERIFY,
        "OP_RETURN": OP_RETURN,
        "OP_TOALTSTACK": OP_TOALTSTACK,
        "OP_FROMALTSTACK": OP_FROMALTSTACK,
        "OP_IFDUP": OP_IFDUP,
        "OP_DEPTH": OP_DEPTH,
        "OP_DROP": OP_DROP,
        "OP_DUP": OP_DUP,
        "OP_NIP": OP_NIP,
        "OP_OVER": OP_OVER,
        "OP_PICK": OP_PICK,
        "OP_ROLL": OP_ROLL,
        "OP_ROT": OP_ROT,
        "OP_SWAP": OP_SWAP,
        "OP_TUCK": OP_TUCK,
        "OP_2DROP": OP_2DROP,
        "OP_2DUP": OP_2DUP,
        "OP_3DUP": OP_3DUP,
        "OP_2OVER": OP_2OVER,
        "OP_2ROT": OP_2ROT,
        "OP_2SWAP": OP_2SWAP,
        "OP_SIZE": OP_SIZE,
        "OP_EQUAL": OP_EQUAL,
        "OP_EQUALVERIFY": OP_EQUALVERIFY,
        "OP_1ADD": OP_1ADD,
        "OP_1SUB": OP_1SUB,
        "OP_NEGATE": OP_NEGATE,
        "OP_ABS": OP_ABS,
        "OP_NOT": OP_NOT,
        "OP_0NOTEQUAL": OP_0NOTEQUAL,
        "OP_ADD": OP_ADD,
        "OP_SUB": OP_SUB,
        "OP_BOOLAND": OP_BOOLAND,
        "OP_BOOLOR": OP_BOOLOR,
        "OP_NUMEQUAL": OP_NUMEQUAL,
        "OP_NUMEQUALVERIFY": OP_NUMEQUALVERIFY,
        "OP_NUMNOTEQUAL": OP_NUMNOTEQUAL,
        "OP_LESSTHAN": OP_LESSTHAN,
        "OP_GREATERTHAN": OP_GREATERTHAN,
        "OP_LESSTHANOREQUAL": OP_LESSTHANOREQUAL,
        "OP_GREATERTHANOREQUAL": OP_GREATERTHANOREQUAL,
        "OP_MIN": OP_MIN,
        "OP_MAX": OP_MAX,
        "OP_WITHIN": OP_WITHIN,
        "OP_RIPEMD160": OP_RIPEMD160,
        "OP_SHA1": OP_SHA1,
        "OP_SHA256": OP_SHA256,
        "OP_HASH160": OP_HASH160,
        "OP_HASH256": OP_HASH256,
        "OP_CODESEPARATOR": OP_CODESEPARATOR,
        "OP_CHECKSIG": OP_CHECKSIG,
        "OP_CHECKSIGVERIFY": OP_CHECKSIGVERIFY,
        "OP_CHECKMULTISIG": OP_CHECKMULTISIG,
        "OP_CHECKMULTISIGVERIFY": OP_CHECKMULTISIGVERIFY,
        "OP_CHECKLOCKTIMEVERIFY": OP_CHECKLOCKTIMEVERIFY,
        "OP_CHECKSEQUENCEVERIFY": OP_CHECKSEQUENCEVERIFY
}

g_pushdata = range(0x01, 0x4b)

g_value_opcode_dict = {v: k for k, v in g_opcode_value_dict.items()}

def get_readable_script(script_b: bytes):
        script_str_list = []
        script_len = len(script_b)
        index = 0
        while index < script_len:
                if script_b[index] in g_pushdata:
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index: index + 1])))
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 1: index + script_b[index] + 1][::-1])))
                        index += 1 + script_b[index]
                elif script_b[index] == OP_PUSHDATA1:
                        script_str_list.append(g_value_opcode_dict[script_b[index]])
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 1: index + 2])))
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 2: index + script_b[index] + 2][::-1])))
                elif script_b[index] == OP_PUSHDATA2:
                        script_str_list.append(g_value_opcode_dict[script_b[index]])
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 1: index + 3])))
                        data_size = int.from_bytes(script_b[index + 1: index + 3], byteorder='big')
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 3: index + data_size + 3][::-1])))
                elif script_b[index] == OP_PUSHDATA4:
                        script_str_list.append(g_value_opcode_dict[script_b[index]])
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 1: index + 5])))
                        data_size = int.from_bytes(script_b[index + 1: index + 5], byteorder='big')
                        script_str_list.append(bytes.decode(binascii.hexlify(script_b[index + 5: index + data_size + 5][::-1])))
                else:
                        script_str_list.append(g_value_opcode_dict[script_b[index]])
                        index += 1
        script_str = ' '.join(script_str_list)
        return script_str

def get_bytes_from_readable_script(script: str):
        pass

def decodeOpN(op_code: int):
        if op_code == OP_0:
                return 0

        return (op_code - (OP_1 - 1))

if __name__ == '__main__':
        print(g_value_opcode_dict)

#        script_b = binascii.unhexlify('76a91460d47ac02b129c08f94232ea506d1826424fe7be88ac')
        script_b = binascii.unhexlify('a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87')
        script_str = get_readable_script(script_b)
        print('script :: %s' % script_str)

        print('OP_0 = %d' % decodeOpN(OP_0))
        print('OP_1NEGATE = %d' % decodeOpN(OP_1NEGATE))
        print('OP_1 = %d' % decodeOpN(OP_1))
        print('OP_2 = %d' % decodeOpN(OP_2))
        print('OP_3 = %d' % decodeOpN(OP_3))
        print('OP_4 = %d' % decodeOpN(OP_4))
        print('OP_5 = %d' % decodeOpN(OP_5))
        print('OP_6 = %d' % decodeOpN(OP_6))
        print('OP_7 = %d' % decodeOpN(OP_7))
        print('OP_8 = %d' % decodeOpN(OP_8))
        print('OP_9 = %d' % decodeOpN(OP_9))
        print('OP_10 = %d' % decodeOpN(OP_10))
        print('OP_11 = %d' % decodeOpN(OP_11))
        print('OP_12 = %d' % decodeOpN(OP_12))
        print('OP_13 = %d' % decodeOpN(OP_13))
        print('OP_14 = %d' % decodeOpN(OP_14))
        print('OP_15 = %d' % decodeOpN(OP_15))
        print('OP_16 = %d' % decodeOpN(OP_16))

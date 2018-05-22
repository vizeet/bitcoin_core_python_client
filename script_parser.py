import binascii
import hashlib
import ecdsa
import leveldb_parser as ldb
from opcode_declarations import * # OPCODE to value assignment such as OP_TRUE = 1
#from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import io
import mmap
import os
from blockfile_parser import getTransactionCount, getCoinbaseTransaction, getBlockHeader
import json

#rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('alice', 'passw0rd'))

#raw_txn_str = '01000000012f03082d300efd92837d3f6d910a21d9d19e868242cfebb21198beed7b440999000000004a493046022100c0f693e024f966dc5f834324baa38426bba05460a2b3f9920989d38322176460022100c523a3aa62da26db1fc1902a93741dce3489629df18be11ba68ff9586041821601ffffffff0100f2052a010000001976a9148773ec867e322378e216eefe55bfcede5263059b88ac00000000'
#raw_txn_str = '01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207ff33f9b7663010000006b483045022100d8629403cd3b49950da9293653c6279149c029e6b7b15371342d0d2ce286c8f2022078787985a644e94fd9246f6c25733336c94af5f00d9d34a07dc2f9e0987ef990012102b726d7eae11a6d5cf3b2362e773e116a6140347dcee1b2943f4a2897351e5d90ffffffff021bf03c000000000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c000000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac00000000'
#txn_hash = '4269fdc239d027922dcec96f1ae283dbaff10e2d1bd49605661d091e79714956'
#txn_hash = '8ca45aed169b0434ad5a117804cdf6eec715208d57f13396c0ba18fb5a327e30' # P2PKH
#txn_hash = '40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8'
txn_hash = '7edb32d4ffd7a385b763c7a8e56b6358bcd729e747290624e18acdbe6209fc45' # P2SH
block_hash = '0000000000000000009a8aa7b36b0e37a28bf98956097b7b844e172692e604e1'


g_script_command_info = {}

def getCount(count_bytes):
        txn_size = count_bytes[0]

        if txn_size < 0xfd:
                return txn_size
        elif txn_size == 0xfd:
                txn_size = int(binascii.hexlify(count_bytes[1:3][::-1]), 16)
                return txn_size
        elif txn_size == 0xfe:
                txn_size = int(binascii.hexlify(count_bytes[1:5][::-1]), 16)
                return txn_size
        else:
                txn_size = int(binascii.hexlify(count_bytes[1:9][::-1]), 16)
                return txn_size

def getCountBytes(mptr: io.BytesIO):
        mptr_read = mptr.read(1)
        count_bytes = mptr_read
        txn_size = int(binascii.hexlify(mptr_read), 16)

        if txn_size < 0xfd:
                return count_bytes
        elif txn_size == 0xfd:
                mptr_read = mptr.read(2)
                count_bytes += mptr_read
                txn_size = int(binascii.hexlify(mptr_read[::-1]), 16)
                return count_bytes
        elif txn_size == 0xfe:
                mptr_read = mptr.read(4)
                count_bytes += mptr_read
                txn_size = int(binascii.hexlify(mptr_read[::-1]), 16)
                return count_bytes
        else:
                mptr_read = mptr.read(8)
                count_bytes += mptr_read
                txn_size = int(binascii.hexlify(mptr_read[::-1]), 16)
                return count_bytes

g_script_sig_dict = {
        'DER': 0x30,
        'INT_VAL': 0x02,
        'SIGHASH_ALL': 0x01,
        'SIGHASH_NONE': 0x02,
        'SIGHASH_SINGLE': 0x03,
        'ANYONECANPAY': 0x80
}

#unlocking script
def getSigFromStack(mptr: io.BytesIO):
        script_len = int.from_bytes(mptr.read(1))
        if g_script_sig_dict['DER'] is int.from_bytes(mptr.read(1)):
                script_sig['seq_type'] = 'DER'
                mptr_read = getCountBytes(mptr)
                sig_size = getCount(mptr_read)
                r_type = int.from_bytes(mptr.read(1)) # this is always 2 and signifies int type
                r_size = int.from_bytes(mptr.read(1))
                if r_size == 0x21:
                        mptr.read(1)
                r = mptr.read(r_size)
                s_type = int.from_bytes(mptr.read(1)) # this is always 2 and signifies int type
                s_size = int.from_bytes(mptr.read(1))
                if s_size == 0x21:
                        mptr.read(1)
                s = mptr.read(s_size)
                sighash_type = mptr.read(1)
                sig = r + s + sighash_type
        return sig

def op_pushdata(mptr: io.BytesIO, code: int, stack: list):
        if code <= 0x4b: # push data
                size = code
        elif code == OP_PUSHDATA1: # OP_PUSHDATA1
                size = int.from_bytes(mptr.read(1), byteorder='big')
        elif code == OP_PUSHDATA2: # OP_PUSHDATA2
                size = int.from_bytes(mptr.read(2), byteorder='big')
        elif code == OP_PUSHDATA4: # OP_PUSHDATA4
                size = int.from_bytes(mptr.read(4), byteorder='big')
        mptr_read = mptr.read(size)
        print('size = %d, data = %s' % (size, bytes.decode(binascii.hexlify(mptr_read))))
        stack.append(mptr_read)

def hash256(bstr):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def getFullPubKeyFromCompressed(x_b: bytes):
        prefix = x_b[0:1]
        print('prefix = %s' % prefix)
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        print('(p+1)/4 = %d' % ((p + 1) >> 2))
        x_b = x_b[1:33]
        x = int.from_bytes(x_b, byteorder='big')

        y_square = (pow(x, 3, p)  + 7) % p
        y_square_square_root = pow(y_square, ((p+1) >> 2), p)
        if (prefix == b"\x02" and y_square_square_root & 1) or (prefix == b"\x03" and not y_square_square_root & 1):
            y = (-y_square_square_root) % p
        else:
            y = y_square_square_root

        y_b = y.to_bytes(32, 'big')
        full_pubkey_b = b''.join([b'\x04', x_b, y_b])
        return full_pubkey_b

def splitSig(complete_sig: bytes):
        sigfp = io.BytesIO(complete_sig)
        der = sigfp.read(1)
        print('der = %s' % bytes.decode(binascii.hexlify(der)))
        sig_len = sigfp.read(1)
        print('sig_len = %d' % int(binascii.hexlify(sig_len), 16))
        int_type = sigfp.read(1)
        print('r int_type = %d' % int(binascii.hexlify(int_type), 16))
        r_len = int(binascii.hexlify(sigfp.read(1)), 16)
        print('r_len = %d' % r_len)
        r = sigfp.read(r_len)
        if r_len == 33:
                r = r[1:33]
        elif r_len < 32:
                r = bytes(32 - r_len) + r
        print('r = %s' % bytes.decode(binascii.hexlify(r)))
        int_type = sigfp.read(1)
        print('s int_type = %d' % int(binascii.hexlify(int_type), 16))
        s_len = int(binascii.hexlify(sigfp.read(1)), 16)
        print('s_len = %d' % s_len)
        s = sigfp.read(s_len)
        if s_len == 33:
                s = s[1:33]
        elif s_len < 32:
                s = bytes(32 - s_len) + s
        print('s = %s' % bytes.decode(binascii.hexlify(s)))
        sighash_type = int(binascii.hexlify(sigfp.read(1)), 16)
        print('sighash_type = %x' % sighash_type)
        return (r, s, sighash_type)

def sigcheck(sig_b: bytes, pubkey_b: bytes, raw_txn_b: bytes):
        txn_sha256_b = hashlib.sha256(raw_txn_b).digest()

        prefix = pubkey_b[0:1]
        print('prefix = %s' % prefix)
        if prefix == b'\x02' or prefix == b'\x03':
                pubkey_b = getFullPubKeyFromCompressed(pubkey_b)[1:]
        elif prefix == b'\x04':
                pubkey_b = pubkey_b[1:]

        print("full public key = %s" % bytes.decode(binascii.hexlify(pubkey_b)))
        vk = ecdsa.VerifyingKey.from_string(pubkey_b, curve=ecdsa.SECP256k1)
        if vk.verify(sig_b, txn_sha256_b, hashlib.sha256) == True:
                print('valid')
                return 1
        else:
                print('invalid')
                return 0

def getTxnSigned(txn: bytes, sighash_type: int, input_index: int):
        txn_signed_b = None
        if sighash_type == g_script_sig_dict['SIGHASH_ALL']:
                txn_signed_b = txn['version']
                if 'is_segwit' in txn:
                        txn_signed_b += b'\x00' + txn['is_segwit']
                txn_signed_b += txn['input_count']
                for index in range(getCount(txn['input_count'])):
                        txn_signed_b += txn['input'][index]['prev_txn_hash']
                        txn_signed_b += txn['input'][index]['prev_txn_out_index']
                        if input_index == index:
                                txn_signed_b += txn['input'][index]['lock_script_size']
                                txn_signed_b += txn['input'][index]['lock_script']
                        else:
                                txn_signed_b += b'\x00'
                        txn_signed_b += txn['input'][index]['sequence']
                txn_signed_b += txn['out_count']
                for index in range(getCount(txn['out_count'])):
                        txn_signed_b += txn['out'][index]['satoshis']
                        txn_signed_b += txn['out'][index]['scriptpubkey_size']
                        txn_signed_b += txn['out'][index]['scriptpubkey']
                txn_signed_b += txn['locktime']
                txn_signed_b += binascii.unhexlify('%08x' % g_script_sig_dict['SIGHASH_ALL'])[::-1]
        print('txn_signed = %s' % bytes.decode(binascii.hexlify(txn_signed_b)))
        return txn_signed_b

def executeScript(script: bytes, stack: list, txn: bytes)
        script_ptr = io.BytesIO(script)
        if_stack = []
        alt_stack = []

        while script_ptr.tell() < script_len:
                code = int(binascii.hexlify(script_ptr.read(1)), 16)
                print ('code = %x' % code)
                print('stack = %s' % stack)
                if len(if_stack) > 0:
                        if if_stack[-1] == OP_FALSE:
                                if code == OP_ELSE:
                                        if_stack.pop()
                                        if_stack.append(OP_TRUE)
                                elif code == OP_ENDIF:
                                        if_stack.pop()
                                else:
                                        pass
                        else:
                                if code == OP_ELSE:
                                        if_stack.pop()
                                        if_stack.append(OP_FALSE)
                                elif code == OP_ENDIF:
                                        if_stack.pop()
                if code == OP_0: # OP_0, OP_FALSE
                        print ('OP_0')
                        stack.append(0)
                elif code <= 0x4e: # push data
                        print ('pushdata')
                        op_pushdata(script_ptr, code, stack)
                elif code == OP_1NEGATE:
                        print ('OP_1NEGATE')
                        stack.append(-1)
                elif code == OP_1: # OP_1, OP_TRUE
                        print ('OP_1')
                        stack.append(1)
                elif code <= OP_16: # OP_2-OP_16
                        print ('OP_2 to OP_16')
                        stack.append(code - 0x50)
                elif code == OP_NOP:
                        print ('OP_NOP')
                        pass
                elif code == OP_IF:
                        print ('OP_IF')
                        if stack[-1] == 0:
                                if_stack.append(OP_FALSE)
                        else:
                                if_stack.append(OP_TRUE)
                elif code == OP_VERIFY:
                        print ('OP_VERIFY')
                        if stack[-1] == 0:
                                return stack, alt_stack, True
                elif code == OP_RETURN:
                        print ('OP_RETURN')
                        op_pushdata(script_ptr, script_ptr.read(1), stack)
                        return stack, alt_stack, True
                elif code == OP_TOALTSTACK:
                        print ('OP_TOALTSTACK')
                        alt_stack.append(stack.pop())
                elif code == OP_FROMALTSTACK:
                        print ('OP_FROMALTSTACK')
                        stack.append(alt_stack.pop())
                elif code == OP_IFDUP:
                        print ('OP_IFDUP')
                        val = stack.pop()
                        if val != 0:
                                stack.append(val)
                                stack.append(val)
                elif code == OP_DEPTH:
                        print ('OP_DEPTH')
                        stack.append(len(stack))
                elif code == OP_DROP:
                        print ('OP_DROP')
                        stack.pop()
                elif code == OP_DUP:
                        print ('OP_DUP')
                        val = stack[-1]
                        stack.append(val)
                elif code == OP_NIP:
                        print ('OP_NIP')
                        stack.pop(-2)
                elif code == OP_OVER:
                        print ('OP_OVER')
                        val = stack[-2]
                        stack.append(val)
                elif code == OP_PICK:
                        print ('OP_PICK')
                        n = int.from_bytes(script_ptr.read(1))
                        val = stack[-1 * n]
                        stack.append(val)
                elif code == OP_ROLL:
                        print ('OP_ROLL')
                        n = int.from_bytes(script_ptr.read(1))
                        val = stack.pop(-1 * n)
                        stack.append(val)
                elif code == OP_ROT:
                        print ('OP_ROT')
                        val = stack.pop(-3)
                        stack.append(val)
                elif code == OP_SWAP:
                        print ('OP_SWAP')
                        val = stack.pop(-2)
                        stack.append(val)
                elif code == OP_TUCK: # x1 x2
                        print ('OP_TUCK')
                        val2 = stack.pop() # val1 = x2
                        val1 = stack.pop() # val2 = x1
                        stack.append(val2) # x2
                        stack.append(val1) # x2 x1
                        stack.append(val2) # x2 x1 x2
                elif code == OP_2DROP:
                        print ('OP_2DROP')
                        stack.pop()
                        stack.pop()
                elif code == OP_2DUP: # x1 x2
                        print ('OP_2DUP')
                        val1 = stack[-2] # x1
                        val2 = stack[-1] # x2
                        stack.append(val1) # x1 x2 x1
                        stack.append(val2) # x1 x2 x1 x2
                elif code == OP_3DUP: # x1 x2 x3
                        print ('OP_3DUP')
                        val1 = stack[-3] # x1
                        val2 = stack[-2] # x2
                        val2 = stack[-1] # x3
                        stack.append(val1) # x1 x2 x3 x1
                        stack.append(val2) # x1 x2 x3 x1 x2
                        stack.append(val3) # x1 x2 x3 x1 x2 x3
                elif code == OP_2OVER: # x1 x2 x3 x4
                        print ('OP_2OVER')
                        val1 = stack[-4] # x1
                        val2 = stack[-3] # x2
                        stack.append(val1) # x1 x2 x3 x4 x1
                        stack.append(val2) # x1 x2 x3 x4 x1 x2
                elif code == OP_2ROT: # x1 x2 x3 x4 x5 x6
                        print ('OP_2ROT')
                        val1 = stack.pop(-6) # x1
                        val2 = stack.pop(-5) # x2
                        stack.append(val1) # x3 x4 x5 x6 x1
                        stack.append(val2) # x3 x4 x5 x6 x1 x2
                elif code == OP_2SWAP: # x1 x2 x3 x4
                        print ('OP_2SWAP')
                        val1 = stack.pop(-4) # x1
                        val2 = stack.pop(-3) # x2
                        stack.append(val1) # x3 x4 x1
                        stack.append(val2) # x3 x4 x1 x2
                elif code == OP_SIZE:
                        print ('OP_SIZE')
                        byte_string = stack[-1]
                        stack.append(len(byte_string))
                elif code == OP_EQUAL: # x1 x2
                        print ('OP_EQUAL')
                        val1 = stack.pop(-2) # x1
                        val2 = stack.pop(-1) # x2
                        if val1 == val2:
                                stack.append(1)
                        else:
                                stack.append(0)
                elif code == OP_EQUALVERIFY: # x1 x2
                        print ('OP_EQUALVERIFY')
                        val1 = stack.pop(-2) # x1
                        val2 = stack.pop(-1) # x2
                        if val1 != val2:
                                return stack, alt_stack, True
                elif code == OP_1ADD:
                        print ('OP_1ADD')
                        val = stack.pop()
                        stack.append(val + 1)
                elif code == OP_1SUB:
                        print ('OP_1SUB')
                        val = stack.pop()
                        stack.append(val - 1)
                elif code == OP_NEGATE:
                        print ('OP_NEGATE')
                        val = stack.pop()
                        stack.append(val * -1)
                elif code == OP_ABS:
                        print ('OP_ABS')
                        val = stack.pop()
                        stack.append(abs(val))
                elif code == OP_NOT:
                        print ('OP_NOT')
                        val = stack.pop()
                        stack.append(int(not val))
                elif code == OP_0NOTEQUAL:
                        print ('OP_0NOTEQUAL')
                        val = stack.pop()
                        stack.append(int(bool(val)))
                elif code == OP_ADD:
                        print ('OP_ADD')
                        val1 = stack.pop()
                        val2 = stack.pop()
                        stack.append(val1 + val2)
                elif code == OP_SUB: # a b
                        print ('OP_SUB')
                        val2 = stack.pop() # b
                        val1 = stack.pop() # a
                        stack.append(val1 - val2) # a - b
                elif code == OP_BOOLAND:
                        print ('OP_BOOLAND')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(bool(val1 and val2))
                elif code == OP_BOOLOR:
                        print ('OP_BOOLOR')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(bool(val1 or val2))
                elif code == OP_NUMEQUAL:
                        print ('OP_NUMEQUAL')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        if val1 == val2:
                                val = 0
                        else:
                                val = 1
                        stack.append(val)
                elif code == OP_NUMEQUALVERIFY:
                        print ('OP_NUMEQUALVERIFY')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        if val1 != val2:
                                return stack, alt_stack, True
                elif code == OP_NUMNOTEQUAL:
                        print ('OP_NUMNOTEQUAL')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(val1 != val2)
                elif code == OP_LESSTHAN:
                        print ('OP_LESSTHAN')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(val1 < val2)
                elif code == OP_GREATERTHAN:
                        print ('OP_GREATERTHAN')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(val1 > val2)
                elif code == OP_LESSTHANOREQUAL:
                        print ('OP_LESSTHANOREQUAL')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(val1 <= val2)
                elif code == OP_GREATERTHANOREQUAL:
                        print ('OP_GREATERTHANOREQUAL')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(val1 >= val2)
                elif code == OP_MIN:
                        print ('OP_MIN')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(min(val1, val2))
                elif code == OP_MAX:
                        print ('OP_MAX')
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.append(max(val1, val2))
                elif code == OP_WITHIN: # x min max
                        print ('OP_WITHIN')
                        maximum = stack.pop()
                        minimum = stack.pop()
                        val = stack.pop()
                        stack.append((val >= minimum) and (val < maximum))
                elif code == OP_RIPEMD160:
                        print ('OP_RIPEMD160')
                        pubkeyhash = stack.pop()
                        h = hashlib.new('ripemd160')
                        h.update(pubkeyhash)
                        ripemd160_hash = h.digest()
                        stack.append(ripemd160_hash)
                elif code == OP_SHA1:
                        print ('OP_SHA1')
                        bstr = stack.pop()
                        stack.append(hashlib.sha1(bstr).digest())
                elif code == OP_SHA256:
                        print ('OP_SHA256')
                        bstr = stack.pop()
                        stack.append(hashlib.sha256(bstr).digest())
                elif code == OP_HASH160:
                        print ('OP_HASH160')
                        pubkey = stack.pop()
                        pubkeyhash = hashlib.sha256(pubkey).digest()
                        h = hashlib.new('ripemd160')
                        h.update(pubkeyhash)
                        pubkey_hash160 = h.digest()
                        stack.append(pubkey_hash160)
                elif code == OP_HASH256:
                        print ('OP_HASH256')
                        pubkey = stack.pop()
                        pubkey_hash256 = hash256(pubkey)
                        stack.append(pubkey_hash256)
                elif code == OP_CODESEPARATOR:
                        print ('OP_CODESEPARATOR')
                        return stack, alt_stack, True # we won't process this as this was widthrawn early in bitcoin
                elif code == OP_CHECKSIG: # sig pubkey
                        print ('OP_CHECKSIG')
                        pubkey_b = stack.pop()
                        complete_sig_b = stack.pop()
                        r, s, sighash_type = splitSig(complete_sig_b)
                        txn_signed_b =  getTxnSigned(txn, sighash_type, input_index)
                        sig_b = r + s
                        is_valid = sigcheck(sig_b, pubkey_b, txn_signed_b)
                        stack.append(is_valid)
                elif code == OP_CHECKSIGVERIFY:
                        print ('OP_CHECKSIGVERIFY')
                        pubkey_b = stack.pop()
                        sig_b = stack.pop() # this is R, S and sig_type
                        r, s, sighash_type = splitSig(complete_sig_b)
                        txn_signed_b =  getTxnSigned(txn, sighash_type, input_index)
                        sig_b = r + s
                        is_valid = sigcheck(sig_b, pubkey_b, txn_signed_b)
                        if is_valid == 0:
                                return stack, alt_stack, True
                elif code == OP_CHECKMULTISIG: # <OP_0> <sig A> <sig B> <OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> <OP_CHECKMULTISIG>
                        print ('OP_CHECKMULTISIG')
                        pubkey_count = stack.pop()
                        pubkey_array = [stack.pop() for index in range(pubkey_count)][::-1]
                        min_valid_sig_count = stack.pop()
                        sig_array = []
                        remaining_valid_sig = min_valid_sig_count
                        while True:
                                sig_b = stack.pop()
                                if sig_b == 0:
                                        sig_array = sig_array[::-1]
                                        break;
                                sig_array.append(sig_b)
                        sig_index = 0
                        is_valid = 0
                        for pubkey_b in pubkey_array:
                                sig_b = sig_array[sig_index]
                                r, s, sighash_type = splitSig(complete_sig_b)
                                txn_signed_b =  getTxnSigned(txn, sighash_type, input_index)
                                sig_b = r + s
                                is_valid_sig = sigcheck(sig_b, pubkey_b, signed_txn)
                                if is_valid_sig == 1:
                                        remaining_valid_sig -= 1
                                        if remaining_valid_sig == 0:
                                                is_valid = 1
                                                break
                                        continue
                        stack.append(is_valid)
                elif code == OP_CHECKMULTISIGVERIFY: # <OP_0> <sig A> <sig B> <OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> <OP_CHECKMULTISIGVERIFY>
                        print ('OP_CHECKMULTISIGVERIFY')
                        pubkey_count = stack.pop()
                        pubkey_array = [stack.pop() for index in range(pubkey_count)][::-1]
                        min_valid_sig_count = stack.pop()
                        sig_array = []
                        remaining_valid_sig = min_valid_sig_count
                        while True:
                                sig_b = stack.pop()
                                if sig_b == 0:
                                        sig_array = sig_array[::-1]
                                        break;
                                sig_array.append(sig_b)
                        sig_index = 0
                        is_valid = 0
                        for pubkey_b in pubkey_array:
                                sig_b = sig_array[sig_index]
                                r, s, sighash_type = splitSig(complete_sig_b)
                                txn_signed_b =  getTxnSigned(txn, sighash_type, input_index)
                                sig_b = r + s
                                is_valid_sig = sigcheck(sig_b, pubkey_b, signed_txn)
                                if is_valid_sig == 1:
                                        remaining_valid_sig -= 1
                                        if remaining_valid_sig == 0:
                                                is_valid = 1
                                                break
                                        continue
                        if is_valid == 0:
                                return stack, alt_stack, True
                elif code == OP_CHECKLOCKTIMEVERIFY: # TODO
                        print ('OP_CHECKLOCKTIMEVERIFY')
                        if len(stack) == 0:
                                return stack, alt_stack, True
                        val = int(binascii.hexlify(stack.pop()[::-1]), 16)
                        if val > n_lock_time or val < 0 or n_sequence == 0xffffffff:
                                return stack, alt_stack, True
                elif code == OP_CHECKSEQUENCEVERIFY: # TODO
                        print ('OP_CHECKSEQUENCEVERIFY')
                        val = int(binascii.hexlify(stack.pop()[::-1]), 16)
                        if val < n_lock_time:
                                return stack, alt_stack, True
                else: # Any non assigned opcode
                        return stack, alt_stack, True

        print('stack = %s' % stack)

        stack.pop()

        return stack, alt_stack, True

def isP2SH(script: bytes):
        if len(script) == 23 and script[0] == OP_HASH160 and script[1] == 0x14 and script[22] == OP_EQUAL:
                print('script is P2SH')
                return True

def verifyScript(txn: dict, input_index: int):
        unlock_script = txn['input'][input_index]['unlock_script']
        lock_script = txn['input'][input_index]['lock_script']

        stack = []

        # execute unlock script
        stack, error = executeScript(unlock_script, stack, txn)

        if error == True:
                return False

        stack_copy = copy.deepcopy(stack)

        is_p2sh = isP2SH(lock_script)

        # execute lock script
        stack, error = executeScript(lock_script, stack, txn)

        if len(stack) == 0:
                return True

        if is_p2sh == True:
                stack = stack_copy
                redeem_script = stack.pop()
                stack, error = executeScript(redeem_script, stack, txn)

                if len(stack) == 0:
                        return True


def convertPKHToAddress(prefix, addr):
    data = prefix + addr
    return base58.b58encode(data + sha256d(data)[:4])

def pubkeyToAddress(pubkey_hex):
        pubkey = bytearray.fromhex(pubkey_hex)
        round1 = hashlib.sha256(pubkey).digest()
        h = hashlib.new('ripemd160')
        h.update(round1)
        pubkey_hash = h.digest()
        return convertPKHToAddress(b'\x00', pubkey_hash)

# returns (lock script, lock script size and satoshis)
def get_prev_txn_info(prev_txn_hash_bigendian: str, prev_txn_out_index: int):
        global g_block_header_size
        block_file_number, block_offset, txn_offset = ldb.getTxnOffset(prev_txn_hash_bigendian)
        print('block_file_number = %d, block_offset = %d, txn_offset = %d' % (block_file_number, block_offset, txn_offset))

        blocks_path = os.path.join(os.getenv('HOME'), '.bitcoin', 'blocks')
        block_filepath = os.path.join(blocks_path, 'blk%05d.dat' % block_file_number)

        with open(block_filepath, 'rb') as block_file:
                txnfp = mmap.mmap(block_file.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only

                txnfp.seek(block_offset + g_block_header_size + txn_offset)

        #        prev_raw_txn = rpc_connection.getrawtransaction(prev_txn_hash)
        #        print('Previous Raw Transaction = %s' % prev_raw_txn)
        #        txnfp = io.BytesIO(binascii.unhexlify(prev_raw_txn))
                skip_txn_version = txnfp.read(4)
                # check input count
                txnfp_read = getCountBytes(txnfp)
                input_count = getCount(txnfp_read)
                if input_count == 0:
                        skip_is_segwit = txnfp.read(1)
                        txnfp_read = getCountBytes(txnfp)
                        input_count = getCount(txnfp_read)
                else:
                        input_count = input_count
                # skip all inputs
                for index in range(input_count):
                        skip_prev_txn = txnfp.read(32+4)
                        txnfp_read = getCountBytes(txnfp)
                        skip_script_size = getCount(txnfp_read)
                        skip_script = txnfp.read(skip_script_size)
                        skip_sequence = txnfp.read(4)

                txnfp_read = getCountBytes(txnfp)
                out_count = getCount(txnfp_read)

                # skip all but required out
                for index in range(out_count):
                        print ('prev_txn_out_index = %d, out_count = %d' % (prev_txn_out_index, out_count))
                        if index != prev_txn_out_index:
                                skip_satoshi = txnfp.read(8)
                                skip_script_size = int(binascii.hexlify(txnfp.read(1)), 16)
                                skip_script = txnfp.read(skip_script_size)
                                continue
                        satoshis = int(binascii.hexlify(txnfp.read(8)[::-1]), 16)
                        lock_script_size_b = getCountBytes(txnfp)
                        lock_script_size = getCount(lock_script_size_b)
                        lock_script = txnfp.read(lock_script_size)
                        break
        return (lock_script, lock_script_size_b, satoshis)

def unlockTxn(mptr: mmap):
        start = mptr
        txn = {}
        txn['version'] = mptr.read(4) # version
        print('txn version = %s' % bytes.decode(binascii.hexlify(txn['version'][::-1])))

        txn['input_count'] = getCountBytes(mptr)
        input_count = getCount(txn['input_count'])
        if input_count == 0:
                # post segwit
                txn['is_segwit'] = mptr.read(1)
                txn['input_count'] = getCountBytes(mptr)
                input_count = getCount(txn['input_count'])

        print('input count = %s' % input_count)

        txn['input'] = []
        for index in range(input_count):
                txn_input = {}
                txn_input['prev_txn_hash'] = mptr.read(32)
                txn_input['prev_txn_out_index'] = mptr.read(4)

                prev_txn_hash = bytes.decode(binascii.hexlify(txn_input['prev_txn_hash'][::-1]))
                prev_txn_out_index = int(binascii.hexlify(txn_input['prev_txn_out_index'][::-1]), 16)

                print('prev txn hash = %s, out index = %d' % (prev_txn_hash, prev_txn_out_index))

                txn_input['unlock_script_size'] = getCountBytes(mptr)
                unlock_script_size = getCount(txn_input['unlock_script_size'])
                txn_input['unlock_script'] = mptr.read(unlock_script_size)
                txn_input['lock_script'], txn_input['lock_script_size'], txn_input['satoshis'] = get_prev_txn_info(txn_input['prev_txn_hash'], prev_txn_out_index)
                print('lock_script = %s, lock_script_size = %d, satoshis = %d' % (bytes.decode(binascii.hexlify(txn_input['lock_script'])), getCount(txn_input['lock_script_size']), txn_input['satoshis']))
                txn_input['sequence'] = mptr.read(4)
                txn['input'].append(txn_input)
        txn['out_count'] = getCountBytes(mptr)
        out_count = getCount(txn['out_count'])
        txn['out'] = []
        for index in range(out_count):
                txn_out = {}
                txn_out['satoshis'] = mptr.read(8)
#                satoshis = int(binascii.hexlify(txn_out['satoshis'][::-1]), 16)
                txn_out['scriptpubkey_size'] = getCountBytes(mptr)
                scriptpubkey_size = getCount(txn_out['scriptpubkey_size'])
                txn_out['scriptpubkey'] = mptr.read(scriptpubkey_size)
                txn['out'].append(txn_out)
        if 'is_segwit' in txn and txn['is_segwit'] == True:
                for index in range(input_count):
                        txn['input'][index]['witness_count'] = getCountBytes(mptr)
                        witness_count = getCount(txn['input'][index]['witness_count'])
                        txn['input'][index]['witness'] = []
                        for inner_index in range(getCount(txn['input'][index]['witness_count'])):
                                txn_witness = {}
                                txn_witness['size'] = getCountBytes(mptr)
                                witness_size = getCount(txn_witness['size'])
                                txn_witness['witness'] = bytes.decode(binascii.hexlify(mptr.read(witness_size)))
                                txn['input'][index]['witness'].append(txn_witness)
        txn['locktime'] = mptr.read(4)
        input_satoshis = sum(txn_input['satoshis'] for txn_input in txn['input'])
        out_satoshis = sum(int(binascii.hexlify(txn_out['satoshis'][::-1]), 16) for txn_out in txn['out'])
        print('Network fees = %d' % (input_satoshis - out_satoshis))
        for index in range(input_count):
                is_p2sh = isP2SH(txn['input'][input_index]['lock_script'])

                status = scriptParser(txn, index)
                print ('status = %s' % status)
                if status == False:
                        print('Invalid Transaction')
                        return (False, 0)
        return (True, input_satoshis - out_satoshis)

g_block_header_size = 80

def validate_all_transactions_of_block(block_hash_bigendian_b: bytes):
        jsonobj = ldb.getBlockIndex(block_hash_bigendian_b)
#                print('n_file = %d' % jsonobj['n_file'])
        print('block index = %s' % json.dumps(jsonobj))
        if 'data_pos' in jsonobj:
                block_filepath = os.path.join(blocks_path, 'blk%05d.dat' % jsonobj['n_file'])
                start = jsonobj['data_pos']
        elif 'undo_pos' in jsonobj:
                block_filepath = os.path.join(blocks_path, 'rev%05d.dat' % jsonobj['n_file'])
                start = jsonobj['undo_pos']

        with open(block_filepath, 'rb') as block_file:
                # load file to memory
                mptr = mmap.mmap(block_file.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only
#                skip_block_header = mptr.read(g_block_header_size)
                mptr.seek(start)
                getBlockHeader(mptr)
                txn_count = getTransactionCount(mptr)
                print('txn_count = %d' % txn_count)
                coinbase_txn = getCoinbaseTransaction(mptr)
                net_fees = 0
                for index in range(1, txn_count):
                        print('XXXXXXXXXXXXXXXX txn index = %d' % index)
                        isValid, satoshis = unlockTxn(mptr)
                        if isValid == False:
                                print('Invalid Transaction')
                                exit()
                        else:
                                print('Valid Transaction')
                        net_fees += satoshis
                print('mining reward = %.8f' % (sum(out['satoshis'] for out in coinbase_txn['out']) / 100000000.0))
                print('net_fees = %.8f' % (net_fees / 100000000.0))

if __name__ == '__main__':
        txn_hash_bigendian = binascii.unhexlify(txn_hash)[::-1]
        block_file_number, block_offset, txn_offset = ldb.getTxnOffset(txn_hash_bigendian)
        print('block_file_number = %d, block_offset = %d, txn_offset = %d' % (block_file_number, block_offset, txn_offset))

        blocks_path = os.path.join(os.getenv('HOME'), '.bitcoin', 'blocks')
        block_filepath = os.path.join(blocks_path, 'blk%05d.dat' % block_file_number)

        with open(block_filepath, 'rb') as block_file:
                mptr = mmap.mmap(block_file.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only

                mptr.seek(block_offset + g_block_header_size + txn_offset)
                isValid = unlockTxn(mptr)
                if isValid == False:
                        print('Invalid Transaction')
                else:
                        print('Valid Transaction')

#        block_hash_bigendian_b = binascii.unhexlify(block_hash)[::-1]
#        validate_all_transactions_of_block(block_hash_bigendian_b)

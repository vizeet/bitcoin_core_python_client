from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

raw_txn_bytes = '01000000012f03082d300efd92837d3f6d910a21d9d19e868242cfebb21198beed7b440999000000004a493046022100c0f693e024f966dc5f834324baa38426bba05460a2b3f9920989d38322176460022100c523a3aa62da26db1fc1902a93741dce3489629df18be11ba68ff9586041821601ffffffff0100f2052a010000001976a9148773ec867e322378e216eefe55bfcede5263059b88ac00000000'

raw_txn = b'\x01\x00\x00\x00\x01/\x03\x08-0\x0e\xfd\x92\x83}?m\x91\n!\xd9\xd1\x9e\x86\x82B\xcf\xeb\xb2\x11\x98\xbe\xed{D\t\x99\x00\x00\x00\x00JI0F\x02!\x00\xc0\xf6\x93\xe0$\xf9f\xdc_\x83C$\xba\xa3\x84&\xbb\xa0T`\xa2\xb3\xf9\x92\t\x89\xd3\x83"\x17d`\x02!\x00\xc5#\xa3\xaab\xda&\xdb\x1f\xc1\x90*\x93t\x1d\xce4\x89b\x9d\xf1\x8b\xe1\x1b\xa6\x8f\xf9X`A\x82\x16\x01\xff\xff\xff\xff\x01\x00\xf2\x05*\x01\x00\x00\x00\x19v\xa9\x14\x87s\xec\x86~2#x\xe2\x16\xee\xfeU\xbf\xce\xdeRc\x05\x9b\x88\xac\x00\x00\x00\x00'

g_script_command_info = {}

G_CODE = 0
G_DATA = 1

def getCount(count_bytes):
        txn_size = int(binascii.hexlify(count_bytes[0:1]), 16)

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

def getCountBytes(mptr: mmap):
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
def getSigFromStack(mptr: mmap):
        script_len = int.from_bytes(mptr.read(1))
        if g_script_sig_dict['DER'] is int.from_bytes(mptr.read(1)):
                script_sig['seq_type'] = 'DER'
                mptr_read = getCountBytes(mptr)
                sig_size = getCount(mptr_read)
                r_type = int.from_bytes(mptr.read(1))
                r_size = int.from_bytes(mptr.read(1))
                if r_size == 0x21:
                        mptr.read(1)
                r = mptr.read(0x20)
                s_type = int.from_bytes(mptr.read(1))
                s_size = int.from_bytes(mptr.read(1))
                if s_size == 0x21:
                        mptr.read(1)
                s = mptr.read(0x20)
                sig = r+s
        return sig

def pushOnStack(stack: list):
        stack.push(mptr.read(size))

def op_pushdata(mptr: mmap, code: int, stack: list)
        elif code <= 0x4b: # push data
                size = code
                stack.push(mptr.read(size))
        elif code == 0x4c: # OP_PUSHDATA1
                size = int.from_bytes(mptr.read(1))
                stack.push(mptr.read(size))
        elif code == 0x4d: # OP_PUSHDATA2
                size = int.from_bytes(mptr.read(2), byteorder='little')
                stack.push(mptr.read(size))
                elif code == 0x4e: # OP_PUSHDATA4
                        size = int.from_bytes(mptr.read(4), byteorder='little')
                        stack.push(mptr.read(size))

def op_verify(stack: list)
        if stack.pop() == True:
                return True
        else:
                return False

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

def scriptParser(mptr: mmap, script_len: int, stack: list, alt_stack: list, signed_txn: bytes, n_lock_time: int, n_sequence: int):
        if_stack = []

        start = mptr.tell()
        while mptr.tell() <= start + script_len:
                code = int.from_bytes(mptr.read(1))
                if len(if_stack) > 0:
                        if if_stack[-1] == OP_FALSE:
                                if code == 0x67: # OP_ELSE
                                        if_stack.pop()
                                        if_stack.push(OP_TRUE)
                                elif code == 0x68: # OP_ENDIF
                                        if_stack.pop()
                                else:
                                        pass
                        else:
                                if code == 0x67: # OP_ELSE
                                        if_stack.pop()
                                        if_stack.push(OP_FALSE)
                                elif code == 0x68: # OP_ENDIF
                                        if_stack.pop()
                if code == 0x00: # OP_0, OP_FALSE
                        stack.push(0)
                elif code <= 0x4e: # push data
                        pushdata_op(mptr, code, stack)
                elif code == 0x4f: # OP_1NEGATE
                        stack.push(-1)
                elif code == 0x51: # OP_1, OP_TRUE
                        stack.push(1)
                elif code <= 0x60: # OP_2-OP_16
                        stack.push(code - 0x50)
                elif code <= 0x61: # OP_NOP
                        pass
                elif code <= 0x63: # OP_IF
                        if_counter += 1
                        if stack[-1] == False:
                                if_stack.push(False)
                        else:
                                if_stack.push(True)
                elif code == 0x69: # OP_VERIFY
                        return op_verify(stack)
                elif code == 0x6a: # OP_RETURN
                        pushdata_op(mptr, mptr.read(1), stack)
                        return False
                elif code == 0x6b: # OP_TOALTSTACK
                        alt_stack.push(stack.pop())
                elif code == 0x6c: # OP_FROMALTSTACK
                        stack.push(alt_stack.pop())
                elif code == 0x73: # OP_IFDUP
                        val = stack.pop()
                        if val != 0:
                                stack.push(val)
                                stack.push(val)
                elif code == 0x74: # OP_DEPTH
                        stack.push(len(stack))
                elif code == 0x75: # OP_DROP
                        stack.pop()
                elif code == 0x76: # OP_DUP
                        val = stack[-1]
                        stack.push(val)
                elif code == 0x77: # OP_NIP
                        stack.pop(-2)
                elif code == 0x78: # OP_OVER
                        val = stack[-2]
                        stack.push(val)
                elif code == 0x79: # OP_PICK
                        n = int.from_bytes(mptr.read(1))
                        val = stack[-1 * n]
                        stack.push(val)
                elif code == 0x7a: # OP_ROLL
                        n = int.from_bytes(mptr.read(1))
                        val = stack.pop(-1 * n)
                        stack.push(val)
                elif code == 0x7b: # OP_ROT
                        val = stack.pop(-3)
                        stack.push(val)
                elif code == 0x7c: # OP_SWAP
                        val = stack.pop(-2)
                        stack.push(val)
                elif code == 0x7d: # OP_TUCK # x1 x2
                        val2 = stack.pop() # val1 = x2
                        val1 = stack.pop() # val2 = x1
                        stack.push(val2) # x2
                        stack.push(val1) # x2 x1
                        stack.push(val2) # x2 x1 x2
                elif code == 0x6d: # OP_2DROP
                        stack.pop()
                        stack.pop()
                elif code == 0x6e: # OP_2DUP x1 x2
                        val1 = stack[-2] # x1
                        val2 = stack[-1] # x2
                        stack.push(val1) # x1 x2 x1
                        stack.push(val2) # x1 x2 x1 x2
                elif code == 0x6f: # OP_3DUP x1 x2 x3
                        val1 = stack[-3] # x1
                        val2 = stack[-2] # x2
                        val2 = stack[-1] # x3
                        stack.push(val1) # x1 x2 x3 x1
                        stack.push(val2) # x1 x2 x3 x1 x2
                        stack.push(val3) # x1 x2 x3 x1 x2 x3
                elif code == 0x70: # OP_2OVER x1 x2 x3 x4
                        val1 = stack[-4] # x1
                        val2 = stack[-3] # x2
                        stack.push(val1) # x1 x2 x3 x4 x1
                        stack.push(val2) # x1 x2 x3 x4 x1 x2
                elif code == 0x71: # OP_2ROT x1 x2 x3 x4 x5 x6
                        val1 = stack.pop(-6) # x1
                        val2 = stack.pop(-5) # x2
                        stack.push(val1) # x3 x4 x5 x6 x1
                        stack.push(val2) # x3 x4 x5 x6 x1 x2
                elif code == 0x72: # OP_2SWAP x1 x2 x3 x4
                        val1 = stack.pop(-4) # x1
                        val2 = stack.pop(-3) # x2
                        stack.push(val1) # x3 x4 x1
                        stack.push(val2) # x3 x4 x1 x2
                elif code == 0x82: # OP_SIZE
                        byte_string = stack[-1]
                        stack.push(len(byte_string))
                elif code == 0x87: # OP_EQUAL x1 x2
                        val1 = stack.pop(-2) # x1
                        val2 = stack.pop(-1) # x2
                        if val1 == val2:
                                stack.push(1)
                        else:
                                stack.push(0)
                elif code == 0x88: # OP_EQUALVERIFY
                        val1 = stack.pop(-2) # x1
                        val2 = stack.pop(-1) # x2
                        if val1 == val2:
                                stack.push(1)
                        else:
                                stack.push(0)
                        return op_verify(stack)
                elif code == 0x8b: # OP_1ADD
                        val = stack.pop()
                        stack.push(val + 1)
                elif code == 0x8c: # OP_1SUB
                        val = stack.pop()
                        stack.push(val - 1)
                elif code == 0x8f: # OP_NEGATE
                        val = stack.pop()
                        stack.push(val * -1)
                elif code == 0x90: # OP_ABS
                        val = stack.pop()
                        stack.push(abs(val))
                elif code == 0x91: # OP_NOT
                        val = stack.pop()
                        stack.push(int(not val))
                elif code == 0x92: # OP_0NOTEQUAL
                        val = stack.pop()
                        stack.push(int(bool(val)))
                elif code == 0x93: # OP_ADD
                        val1 = stack.pop()
                        val2 = stack.pop()
                        stack.push(val1 + val2)
                elif code == 0x94: # OP_SUB a b
                        val2 = stack.pop() # b
                        val1 = stack.pop() # a
                        stack.push(val1 - val2) # a - b
                elif code == 0x9a: # OP_BOOLAND
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(bool(val1 and val2))
                elif code == 0x9b: # OP_BOOLOR
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(bool(val1 or val2))
                elif code == 0x9c: # OP_NUMEQUAL
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 == val2)
                elif code == 0x9d: # OP_NUMEQUALVERIFY
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 == val2)
                        return op_verify(stack)
                elif code == 0x9e: # OP_NUMNOTEQUAL
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 != val2)
                elif code == 0x9f: # OP_LESSTHAN
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 < val2)
                elif code == 0xa0: # OP_GREATERTHAN
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 > val2)
                elif code == 0xa1: # OP_LESSTHANOREQUAL
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 <= val2)
                elif code == 0xa2: # OP_GREATERTHANOREQUAL
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(val1 >= val2)
                elif code == 0xa3: # OP_MIN
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(min(val1, val2))
                elif code == 0xa4: # OP_MAX
                        val2 = stack.pop()
                        val1 = stack.pop()
                        stack.push(max(val1, val2))
                elif code == 0xa5: # OP_WITHIN x min max
                        maximum = stack.pop()
                        minimum = stack.pop()
                        val = stack.pop()
                        stack.push((val >= minimum) and (val < maximum))
                elif code == 0xa6: # OP_RIPEMD160
                        pubkeyhash = stack.pop()
                        h = hashlib.new('ripemd160')
                        h.update(pubkeyhash)
                        ripemd160_hash = h.digest()
                        stack.push(ripemd160_hash)
                elif code == 0xa7: # OP_SHA1
                        bstr = stack.pop()
                        stack.push(hashlib.sha1(bstr).digest())
                elif code == 0xa8: # OP_SHA256
                        bstr = stack.pop()
                        stack.push(hashlib.sha256(bstr).digest())
                elif code == 0xa9: # OP_HASH160
                        pubkey = stack.pop()
                        pubkeyhash = hashlib.sha256(pubkey).digest()
                        h = hashlib.new('ripemd160')
                        h.update(pubkeyhash)
                        pubkey_hash160 = h.digest()
                        stack.push(pubkey_hash160)
                elif code == 0xaa: # OP_HASH256
                        pubkey = stack.pop()
                        pubkey_hash256 = hash256(pubkey)
                        stack.push(pubkey_hash256)
                elif code == 0xab: # OP_CODESEPARATOR TODO
                        pass
                elif code == 0xac: # OP_CHECKSIG sig pubkey
                        pubkey_b = stack.pop()
                        sig_b = stack.pop()
                        is_valid = sigcheck(sig_b, pubkey_b, signed_txn)
                        stack.push(is_valid)
                elif code == 0xad: # OP_CHECKSIGVERIFY
                        pubkey_b = stack.pop()
                        sig_b = stack.pop()
                        is_valid = sigcheck(sig_b, pubkey_b, signed_txn)
                        stack.push(is_valid)
                        return op_verify(stack)
                elif code == 0xae: # OP_CHECKMULTISIG <OP_0> <sig A> <sig B> <OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> <OP_CHECKMULTISIG>
                        pubkey_count = stack.pop() - OP_0
                        pubkey_array = [stack.pop() for index in range(pubkey_count)][::-1]
                        min_valid_sig_count = stack.pop() - OP_0
                        sig_array = []
                        remaining_valid_sig = min_valid_sig_count
                        while True:
                                sig_b = stack.pop()
                                if sig_b == OP_0:
                                        sig_array = sig_array[::-1]
                                        break;
                                sig_array.append(sig_b)
                        sig_index = 0
                        is_valid = 0
                        for pubkey_b in pubkey_array:
                                sig_b = sig_array[sig_index]
                                is_valid_sig = sigcheck(sig_b, pubkey_b, signed_txn)
                                if is_valid_sig == 1:
                                        remaining_valid_sig -= 1
                                        if remaining_valid_sig == 0:
                                                is_valid = 1
                                                break
                                        continue
                        stack.push(is_valid)
                elif code == 0xaf: # OP_CHECKMULTISIGVERIFY <OP_0> <sig A> <sig B> <OP_2> <A pubkey> <B pubkey> <C pubkey> <OP_3> <OP_CHECKMULTISIGVERIFY>
                        pubkey_count = stack.pop() - OP_0
                        pubkey_array = [stack.pop() for index in range(pubkey_count)][::-1]
                        min_valid_sig_count = stack.pop() - OP_0
                        sig_array = []
                        remaining_valid_sig = min_valiv_sig_count
                        while True:
                                sig_b = stack.pop()
                                if sig_b == OP_0:
                                        sig_array = sig_array[::-1]
                                        break;
                                sig_array.append(sig_b)
                        sig_index = 0
                        is_valid = 0
                        for pubkey_b in pubkey_array:
                                sig_b = sig_array[sig_index]
                                is_valid_sig = sigcheck(sig_b, pubkey_b, signed_txn)
                                if is_valid_sig == 1:
                                        remaining_valid_sig -= 1
                                        if remaining_valid_sig == 0:
                                                is_valid = 1
                                                break
                                        continue
                        stack.push(is_valid)
                        return op_verify(stack)
                elif code == 0xb1: # OP_CHECKLOCKTIMEVERIFY TODO
                        if len(stack) == 0:
                                return False
                        val = int(binascii.hexlify(stack.pop()[::-1]), 16)
                        if val > n_lock_time or val < 0 or n_sequence == 0xffffffff:
                                return False
                elif code == 0xb2: # OP_CHECKSEQUENCEVERIFY TODO
                        val = int(binascii.hexlify(stack.pop()[::-1]), 16)
                        if val < n_lock_time:
                                return False
                else: # Any non assigned opcode
                        return False

        mptr.read(script_len)
        

def scriptPubkeyParser(scriptPubKey: str, txn: bytes):
        pass

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

def getTransaction(mptr: mmap):
        txn = {}
        mptr_read = mptr.read(4)
        raw_txn = mptr_read
        raw_txn_for_sign = mptr_read
        txn['version'] = int(binascii.hexlify(mptr_read[::-1]), 16)
        mptr_read = getCountBytes(mptr)
        input_count = getCount(mptr_read)
        if input_count == 0:
                # post segwit
                txn['is_segwit'] = bool(int(binascii.hexlify(mptr.read(1)), 16))
                mptr_read = getCountBytes(mptr)
                txn['input_count'] = getCount(mptr_read)
        else:
                txn['input_count'] = input_count
        raw_txn += mptr_read
        raw_txn_for_sign += mptr_read
        txn['input'] = []
        for index in range(txn['input_count']):
                txn_input = {}
                mptr_read = mptr.read(32)
                raw_txn += mptr_read
                raw_txn_for_sign += mptr_read
                txn_input['prev_txn_hash'] = bytes.decode(binascii.hexlify(mptr_read[::-1]))
                mptr_read = mptr.read(4)
                raw_txn += mptr_read
                raw_txn_for_sign += mptr_read
                txn_input['prev_txn_out_index'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                parsed_sig = scriptSigParser(mptr)
#                mptr_read = getCountBytes(mptr)
#                raw_txn += mptr_read
#                txn_input['scriptsig_size'] = getCount(mptr_read)
#                mptr_read = mptr.read(txn_input['scriptsig_size'])
#                raw_txn += mptr_read
#                txn_input['scriptsig'] = bytes.decode(binascii.hexlify(mptr_read))
                mptr_read = mptr.read(4)
                raw_txn += mptr_read
                raw_txn_for_sign += mptr_read
                txn_input['sequence'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                txn['input'].append(txn_input)
        mptr_read = getCountBytes(mptr)
        raw_txn += mptr_read
        txn['out_count'] = getCount(mptr_read)
        txn['out'] = []
        for index in range(txn['out_count']):
                txn_out = {}
                mptr_read = mptr.read(8)
                raw_txn += mptr_read
                txn_out['_satoshis'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                txn_out['scriptpubkey_size'] = getCount(mptr_read)
                mptr_read = mptr.read(txn_out['scriptpubkey_size'])
                raw_txn += mptr_read
                txn_out['scriptpubkey'] = bytes.decode(binascii.hexlify(mptr_read))
                txn['out'].append(txn_out)
        if 'is_segwit' in txn and txn['is_segwit'] == True:
                for index in range(txn['input_count']):
                        mptr_read = getCountBytes(mptr)
                        txn['input'][index]['witness_count'] = getCount(mptr_read)
                        txn['input'][index]['witness'] = []
                        for inner_index in range(txn['input'][index]['witness_count']):
                                txn_witness = {}
                                mptr_read = getCountBytes(mptr)
                                txn_witness['size'] = getCount(mptr_read)
                                txn_witness['witness'] = bytes.decode(binascii.hexlify(mptr.read(txn_witness['size'])))
                                txn['input'][index]['witness'].append(txn_witness)
        mptr_read = mptr.read(4)
        raw_txn += mptr_read
        txn['locktime'] = int(binascii.hexlify(mptr_read[::-1]), 16)
        txn['txn_hash'] = getTxnHash(raw_txn)

        logging.debug(json.dumps(txn, indent=4))
        logging.debug('raw_txn_str = %s' % bytes.decode(binascii.hexlify(raw_txn)))
        logging.debug('raw_txn_bytes = %s' % raw_txn)

#        check_raw_txn = rpc_connection.getrawtransaction(txn['txn_hash'])
#        logging.debug('blockfile index = %d' % g_blockfile_index)
#        logging.debug('block index = %d' % g_block_index)
#        logging.debug('txn index = %d' % g_txn_index)
#        logging.debug('block_header_hash = %s' % g_block_header_hash)
#        logging.debug('checked raw txn = %s' % check_raw_txn)
#        logging.debug('txn_hash = %s' % txn['txn_hash'])
#        logging.debug('raw_txn = %s' % bytes.decode(binascii.hexlify(raw_txn)))
        return txn

if __name__ == '__main__':
        with mmap.mmap(-1, 1000) as mm:
                mm.write(raw_txn)

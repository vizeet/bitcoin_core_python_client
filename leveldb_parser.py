import plyvel
import os
import binascii
import json

# Open the LevelDB
block_db = plyvel.DB(os.path.join(os.getenv('HOME'),".bitcoin/blocks/index"), compression=None)
chainstate_db = plyvel.DB(os.path.join(os.getenv('HOME'),".bitcoin/chainstate"), compression=None)

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

#template<typename Stream, VarIntMode Mode, typename I>
#void WriteVarInt(Stream& os, I n)
#{
#    CheckVarIntMode<Mode, I>();
#    unsigned char tmp[(sizeof(n)*8+6)/7];
#    int len=0;
#    while(true) {
#        tmp[len] = (n & 0x7F) | (len ? 0x80 : 0x00);
#        if (n <= 0x7F)
#            break;
#        n = (n >> 7) - 1;
#        len++;
#    }
#    do {
#        ser_writedata8(os, tmp[len]);
#    } while(len--);
#}

def b128_varint_encode(n: int):
    """ Performs the MSB base-128 encoding of a given value. Used to store variable integers (varints) in the LevelDB.
    The code is a port from the Bitcoin Core C++ source. Notice that the code is not exactly the same since the original
    one reads directly from the LevelDB.

    The encoding is used to store Satoshi amounts into the Bitcoin LevelDB (chainstate). Before encoding, values are
    compressed using txout_compress.

    The encoding can also be used to encode block height values into the format use in the LevelDB, however, those are
    encoded not compressed.

    Explanation can be found in:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L307L329
    And code:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L343#L358

    The MSB of every byte (x)xxx xxxx encodes whether there is another byte following or not. Hence, all MSB are set to
    one except from the very last. Moreover, one is subtracted from all but the last digit in order to ensure a
    one-to-one encoding. Hence, in order decode a value, the MSB is changed from 1 to 0, and 1 is added to the resulting
    value. Then, the value is multiplied to the respective 128 power and added to the rest.

    Examples:

        - 255 = 807F (0x80 0x7F) --> (1)000 0000 0111 1111 --> 0000 0001 0111 1111 --> 1 * 128 + 127 = 255
        - 4294967296 (2^32) = 8EFEFEFF (0x8E 0xFE 0xFE 0xFF 0x00) --> (1)000 1110 (1)111 1110 (1)111 1110 (1)111 1111
            0000 0000 --> 0000 1111 0111 1111 0111 1111 1000 0000 0000 0000 --> 15 * 128^4 + 127*128^3 + 127*128^2 +
            128*128 + 0 = 2^32


    :param n: Value to be encoded.
    :type n: int
    :return: The base-128 encoded value
    :rtype: hex str
    """
    l = 0
    tmp = []
    data = ""
    ret = bytes(0)
    while True:
        tmp.insert(0, n & 0x7F)
        if l != 0:
            tmp[0] |= 0x80
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1

    bin_data = bytes(tmp)
    return bin_data

def b128_varint_decode(value: bytes, pos = 0):
    """
    Reads the weird format of VarInt present in src/serialize.h of bitcoin core
    and being used for storing data in the leveldb.
    This is not the VARINT format described for general bitcoin serialization
    use.
    """
    n = 0
    while True:
        data = value[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f) # 1111111
        if data & 0x80 == 0: # each byte is greater than or equal to 0x80 except at the end
            return (n, pos)
        n += 1

def amount_compress(n: int):
    if n == 0:
        return 0
    e = 0
    while ((n % 10) == 0) and e < 9:
        n = int(n / 10)
        e += 1
    if e < 9:
        d = n % 10
        assert(d >= 1 and d <= 9)
        n = int(n / 10)
        return 1 + (n*9 + d - 1)*10 + e
    else:
        return 1 + (n - 1)*10 + 9

def amount_decompress(x: int):
    print('1 x = %d' % x)
    # x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if x == 0:
        return 0
    x -=1
    # x = 10*(9*n + d - 1) + e
    e = x % 10
    print('e = %d' % e)
    x = int(x / 10)
    print('2 x = %d' % x)
    n = 0
    if e < 9:
        # x = 9*n + d - 1
        d = (x % 9) + 1
        print('1 d = %d' % d)
        x = int(x / 9)
        print('3 x = %f' % x)
        # x = n
        n = x*10 + d
        print('1 n = %d' % n)
    else:
        n = x+1
    while e:
        n *= 10
        e -= 1
    return n

def check_varint(num: int):
        var_bytes = b128_varint_encode(num)
        print('varint_encoded = %s' % var_bytes)
        new_num, pos = b128_varint_decode(var_bytes)
        print('varint_decoded = %d' % new_num)

def getObfuscationKey():
        value = chainstate_db.get(b'\x0e\x00' + b'obfuscate_key')
        print('obfuscation key = %s' % value)
        obfuscation_key = value[1:]
        return obfuscation_key

def applyObfuscationKey(data: bytes):
        obfuscation_key = getObfuscationKey()
        new_val = bytes(data[index] ^ obfuscation_key[index % len(obfuscation_key)] for index in range(len(data)))
        return new_val

nSpecialScripts = 6 # predefined types of scripts
#unsigned int GetSpecialScriptSize(unsigned int nSize)
#{
#    if (nSize == 0 || nSize == 1)
#        return 20;
#    if (nSize == 2 || nSize == 3 || nSize == 4 || nSize == 5)
#        return 32;
#    return 0;
#}

#bool DecompressScript(CScript& script, unsigned int nSize, const std::vector<unsigned char> &in)
#{
#    switch(nSize) {
#    case 0x00:
#        script.resize(25);
#        script[0] = OP_DUP;
#        script[1] = OP_HASH160;
#        script[2] = 20;
#        memcpy(&script[3], in.data(), 20);
#        script[23] = OP_EQUALVERIFY;
#        script[24] = OP_CHECKSIG;
#        return true;
#    case 0x01:
#        script.resize(23);
#        script[0] = OP_HASH160;
#        script[1] = 20;
#        memcpy(&script[2], in.data(), 20);
#        script[22] = OP_EQUAL;
#        return true;
#    case 0x02:
#    case 0x03:
#        script.resize(35);
#        script[0] = 33;
#        script[1] = nSize;
#        memcpy(&script[2], in.data(), 32);
#        script[34] = OP_CHECKSIG;
#        return true;
#    case 0x04:
#    case 0x05:
#        unsigned char vch[33] = {};
#        vch[0] = nSize - 2;
#        memcpy(&vch[1], in.data(), 32);
#        CPubKey pubkey(&vch[0], &vch[33]);
#        if (!pubkey.Decompress())
#            return false;
#        assert(pubkey.size() == 65);
#        script.resize(67);
#        script[0] = 65;
#        memcpy(&script[1], pubkey.begin(), 65);
#        script[66] = OP_CHECKSIG;
#        return true;

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

def uncompressScript(script_type: int, script_data: bytes):
        if script_type == 0:
                script = bytes([
                        0x76, # OP_DUP
                        0xa9, # OP_HASH160
                        20 # size
                        ]) + script_data + bytes([
                        0x88, # OP_EQUALVERIFY
                        0xac # OP_CHECKSIG
                        ])
        elif script_type == 1:
                script = bytes([
                        0xa9, # OP_HASH160
                        20 # size
                        ]) + script_data + bytes([
                        0x87, # OP_EQUAL
                        ])
        elif script_type in [2, 3]:
                script = bytes([
                        33, # size
                        script_type
                        ]) + script_data + bytes([
                        0xac # OP_CHECKSIG
                        ])
        elif script_type in [4, 5]: # script_type = 4 means y is odd and script_type = 5 means y is even in compressed pubkey
                compressed_pubkey = bytes([script_type - 2]) + script_data
                pubkey = getFullPubKeyFromCompressed(compressed_pubkey)
                script = bytes([
                        65 # size
                        ]) + pubkey + bytes([
                        0xac # OP_CHECKSIG
                        ])
        else: 
                script = script_data
 
        return script

def getChainstateData(txn_hash_big_endian: bytes, out_index: int):
        jsonobj = {}
        key = b'C' + txn_hash_big_endian + b128_varint_encode(out_index)
#        print(key)
        value = chainstate_db.get(key)
        value = applyObfuscationKey(value)
        print('chainstate (key, value) = (%s, %s)' % (key, value))
        code, pos = b128_varint_decode(value)
        jsonobj['height'] = code >> 1
        jsonobj['is_coinbase'] = code & 0x01
        compressed_amount, pos = b128_varint_decode(value, pos)
        jsonobj['amount'] = amount_decompress(compressed_amount)
        jsonobj['script_type'], pos = b128_varint_decode(value, pos)
        jsonobj['script'] = uncompressScript(jsonobj['script_type'], value[pos:])
        print('script = %s' % bytes.decode(binascii.hexlify(jsonobj['script'])))
        return jsonobj

def getIterateChainstateDB():
        it = chainstate_db.iterator(include_value=False)
        while True:
                key = next(it)
                prefix = key[0:1]
                if prefix == b'C':
                        out_index, pos = b128_varint_decode(key[33:])
#                        print('txn_id = %s, out_index = %s' % (bytes.decode(binascii.hexlify(key[1:33][::-1])), out_index))
                        print('txn_id_big_endian = %s, out_index = %s' % (bytes.decode(binascii.hexlify(key[1:33])), out_index))

def getLastBlockFile():
        last_blockfile_number = int(binascii.hexlify(block_db.get(b'l')[::-1]), 16)
        return last_blockfile_number

def getBlockIndex(block_hash_bigendian: bytes):
        key = b'b' + block_hash_bigendian
#        print(key)
        value = block_db.get(key)
        jsonobj = {}
        jsonobj['version'], pos = b128_varint_decode(value)
        jsonobj['height'], pos = b128_varint_decode(value, pos)
        jsonobj['status'], pos = b128_varint_decode(value, pos)
        jsonobj['txn_count'], pos = b128_varint_decode(value, pos)
        if jsonobj['status'] & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
                jsonobj['n_file'], pos = b128_varint_decode(value, pos)
        if jsonobj['status'] & BLOCK_HAVE_DATA:
                jsonobj['data_pos'], pos = b128_varint_decode(value, pos)
        if jsonobj['status'] & BLOCK_HAVE_UNDO:
                jsonobj['undo_pos'], pos = b128_varint_decode(value, pos)
        return jsonobj

# Returns block file, block index and txn index
def getTxnOffset(txn_hash_bigendian: bytes):
        key = b't' + txn_hash_bigendian
#        print(key)
        value = block_db.get(key)
        block_file_number, pos = b128_varint_decode(value, 0)
        block_offset, pos = b128_varint_decode(value, pos)
        txn_offset, pos = b128_varint_decode(value, pos)
#        print('key = %s, txn_hash = %s, block_file_number = %d, block_offset = %d, tx_offset = %d' % (bytes.decode(binascii.hexlify(key)), bytes.decode(binascii.hexlify(txn_hash_bigendian[::-1])), block_file_number, block_offset, txn_offset))
        return block_file_number, block_offset, txn_offset

def isTxindex():
        key = b'F' + b'\x07' + b'txindex'
        print(key)
        value = block_db.get(key)
        if value == b'1':
                return True
        else:
                return False

def getRecentBlockHash():
        key = b'B'
#        print(key)
        block_hash_b = chainstate_db.get(key)
        block_hash_b = applyObfuscationKey(block_hash_b)
        return block_hash_b

if __name__ == '__main__':
        txn_hash_str = 'd6030272a4e430b293c7f6152398ea47d8485e2e8c1719f841c9665ffee6a237'
        t = binascii.unhexlify(txn_hash_str)[::-1]
        blockfile_number, block_offset, txn_offset = getTxnOffset(t)
        print('txn_hash_str = %s, block_file_number = %d, block_offset = %d, tx_offset = %d' % (txn_hash_str, blockfile_number, block_offset, txn_offset))

        block_hash_str = '0000000000000000002520cefdd338334a3160bc5562b8cfd06a3ebba6919c24'
        block_hash_bigendian = binascii.unhexlify(block_hash_str)[::-1]
        blockindex_json = getBlockIndex(block_hash_bigendian)
        print('block_hash_str = %s, block index json = %s' % (block_hash_str, blockindex_json))

        last_block_index = getLastBlockFile()
        print('last block index = %d' % last_block_index)

        if isTxindex() == True:
                print('txindex is enabled')
        else:
                print('txindex is disabled')
        block_hash_b = getRecentBlockHash()
        print('Latest stored block hash = %s' % bytes.decode(binascii.hexlify(block_hash_b[::-1])))
        check_varint(2000000)
#        getIterateChainstateDB()
        print('....txn_id = %s' % bytes.decode(binascii.hexlify(binascii.unhexlify('0060c16adcf98e70c1d9e8c971ad9f27d3363394993156691ec9f3a46c4c4a4d')[::-1])))
        jsonobj = getChainstateData(binascii.unhexlify('0060c16adcf98e70c1d9e8c971ad9f27d3363394993156691ec9f3a46c4c4a4d'), 1822)
        print(jsonobj)

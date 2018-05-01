import plyvel
import os
import binascii

# Open the LevelDB
block_db = plyvel.DB(os.path.join(os.getenv('HOME'),".bitcoin/blocks/index"), compression=None)
chainstate_db = plyvel.DB(os.path.join(os.getenv('HOME'),".bitcoin/chainstate"), compression=None)

def read_varint(raw_hex, pos):
    """
    Reads the weird format of VarInt present in src/serialize.h of bitcoin core
    and being used for storing data in the leveldb.
    This is not the VARINT format described for general bitcoin serialization
    use.
    """
    n = 0
    while True:
        data = raw_hex[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

def getLastBlockFile():
        last_blockfile_number = int(binascii.hexlify(block_db.get(b'l')[::-1]), 16)
        return last_blockfile_number

def getBlockIndex(block_hash_bigendian: bytes):
        key = b'b' + block_hash_bigendian
#        print(key)
        value = block_db.get(key)
        jsonobj = {}
        jsonobj['version'], pos = read_varint(value, 0)
        jsonobj['height'], pos = read_varint(value, pos)
        jsonobj['status'], pos = read_varint(value, pos)
        jsonobj['txn_count'], pos = read_varint(value, pos)
        if jsonobj['status'] & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
                jsonobj['n_file'], pos = read_varint(value, pos)
        if jsonobj['status'] & BLOCK_HAVE_DATA:
                jsonobj['data_pos'], pos = read_varint(value, pos)
        if jsonobj['status'] & BLOCK_HAVE_UNDO:
                jsonobj['undo_pos'], pos = read_varint(value, pos)
        return jsonobj

# Returns block file, block index and txn index
def getTxnOffset(txn_hash_bigendian: bytes):
        key = b't' + txn_hash_bigendian
#        print(key)
        value = block_db.get(key)
        block_file_number, pos = read_varint(value, 0)
        block_offset, pos = read_varint(value, pos)
        txn_offset, pos = read_varint(value, pos)
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

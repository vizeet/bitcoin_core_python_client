from blockfile_parser import getBlock, getBlockHeader
from leveldb_parser import getBlockIndex, getRecentBlockHash
import os
import mmap
import binascii

blocks_path = os.path.join(os.getenv('HOME'), '.bitcoin', 'blocks')

def traverse_blockchain_in_reverse():
        next_block_hash_bigendian_b = getRecentBlockHash()
        print('next block hash = %s' % bytes.decode(binascii.hexlify(next_block_hash_bigendian_b[::-1])))
        while True:
                jsonobj = getBlockIndex(next_block_hash_bigendian_b)
#                print('n_file = %d' % jsonobj['n_file'])
                if 'data_pos' in jsonobj:
                        block_filepath = os.path.join(blocks_path, 'blk%05d.dat' % jsonobj['n_file'])
                        start = jsonobj['data_pos']
                elif 'undo_pos' in jsonobj:
                        block_filepath = os.path.join(blocks_path, 'rev%05d.dat' % jsonobj['n_file'])
                        start = jsonobj['undo_pos']

                with open(block_filepath, 'rb') as block_file:
                        # load file to memory
                        mptr = mmap.mmap(block_file.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only
                        block = getBlock(mptr, start - 8)
                        print('magic number = %s' % (block['block_pre_header']['magic_number']))
                        next_block_hash = block['block_header']['prev_block_hash']
                        print('next block hash = %s, n_file = %d, height = %d' % (next_block_hash, jsonobj['n_file'], jsonobj['height']))
                        next_block_hash_bigendian_b = binascii.unhexlify(next_block_hash)[::-1]
                if jsonobj['height'] == 1:
                        break

if __name__ == '__main__':
        traverse_blockchain_in_reverse()
        

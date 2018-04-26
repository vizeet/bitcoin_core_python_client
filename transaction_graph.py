import os
import mmap
import binascii
import os
import glob
import binascii
import datetime
import shutil
import mmap
import hashlib
import json
from py2neo import Graph, authenticate, Cursor, cypher
import logging
import csv
import pandas as pd
import numpy as np

#from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

#rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('alice', 'passw0rd'))

graph = Graph(host='localhost',
              bolt=True,
              bolt_port=7687,
              http_port=7474,
              secure=False,
              user='neo4j',
              password='passw0rd')

blocks_dir = os.path.join(os.getenv('HOME'), '.bitcoin', 'blocks')

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

def getTxnHash(txn: bytes):
        txn_hash = hashlib.sha256(hashlib.sha256(txn).digest()).digest()
        return bytes.decode(binascii.hexlify(txn_hash[::-1]))

def getTransactionCount(mptr: mmap):
        count_bytes = getCountBytes(mptr)
        txn_count = getCount(count_bytes)
        return txn_count

def getCoinbaseTransaction(mptr: mmap):
        txn = {}
        raw_txn = mptr.read(4)
        mptr_read = getCountBytes(mptr)
        input_count = getCount(mptr_read)
        if input_count == 0:
                # post segwit
                is_segwit = bool(int(binascii.hexlify(mptr.read(1)), 16))
                mptr_read = getCountBytes(mptr)
                input_count = getCount(mptr_read)
        raw_txn += mptr_read
        txn['input'] = []
        for index in range(input_count):
                txn_input = {}
                mptr_read = mptr.read(32)
                raw_txn += mptr_read
                txn_input['prev_txn_hash'] = bytes.decode(binascii.hexlify(mptr_read[::-1]))
                mptr_read = mptr.read(4)
                raw_txn += mptr_read
                txn_input['prev_txn_out_index'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                coinbase_data_size = getCount(mptr_read)
                fptr1 = mptr.tell()
                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                raw_txn += mptr.read(getCount(mptr_read))
                fptr2 = mptr.tell()
                arbitrary_data_size = coinbase_data_size - (fptr2 - fptr1)
                raw_txn += mptr.read(arbitrary_data_size)
                raw_txn += mptr.read(4)
                txn['input'].append(txn_input)
        mptr_read = getCountBytes(mptr)
        raw_txn += mptr_read
        out_count = getCount(mptr_read)
        txn['out'] = []
        for index in range(out_count):
                txn_out = {}
                mptr_read = mptr.read(8)
                raw_txn += mptr_read
                txn_out['satoshis'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                scriptpubkey_size = getCount(mptr_read)
                mptr_read = mptr.read(scriptpubkey_size)
                raw_txn += mptr_read
                txn_out['scriptpubkey'] = bytes.decode(binascii.hexlify(mptr_read))
                txn['out'].append(txn_out)
        if 'is_segwit' in txn and is_segwit == True:
                for index in range(input_count):
                        count_bytes = getCountBytes(mptr)
                        witness_count = getCount(count_bytes)
                        txn['input'][index]['witness'] = []
                        for inner_index in range(witness_count):
                                txn_witness = {}
                                count_bytes = getCountBytes(mptr)
                                witness_size = getCount(count_bytes)
                                txn_witness['witness'] = bytes.decode(binascii.hexlify(mptr.read(witness_size)))
                                txn['input'][index]['witness'].append(txn_witness)
        mptr_read = mptr.read(4)
        raw_txn += mptr_read
        txn['txn_hash'] = getTxnHash(raw_txn)
        return txn

def getTransaction(mptr: mmap):
        txn_id = set()
        out = {}
        inputs = {}
        txn = {}
        raw_txn = mptr.read(4)
        mptr_read = getCountBytes(mptr)
        input_count = getCount(mptr_read)
        if input_count == 0:
                # post segwit
                is_segwit = bool(int(binascii.hexlify(mptr.read(1)), 16))
                mptr_read = getCountBytes(mptr)
                input_count = getCount(mptr_read)
        raw_txn += mptr_read

        txn['input'] = []
        input_list = []
        for index in range(input_count):
                txn_input = {}
                mptr_read = mptr.read(32)
                raw_txn += mptr_read
                txn_input['prev_txn_hash'] = bytes.decode(binascii.hexlify(mptr_read[::-1]))
                txn_id.add(txn_input['prev_txn_hash'])
                mptr_read = mptr.read(4)
                raw_txn += mptr_read
                txn_input['prev_txn_out_index'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                out_id = "%s_%d" % (txn_input['prev_txn_hash'], txn_input['prev_txn_out_index'])
                if out_id not in out:
                        out[out_id] = {}
                        out[out_id]['index'] = txn_input['prev_txn_out_index']
                        out[out_id]['satoshis'] = -1

                input_list.append(out_id)

                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                scriptsig_size = getCount(mptr_read)
                mptr_read = mptr.read(scriptsig_size)
                raw_txn += mptr_read
                txn_input['scriptsig'] = bytes.decode(binascii.hexlify(mptr_read))
                raw_txn += mptr.read(4)
                txn['input'].append(txn_input)
        mptr_read = getCountBytes(mptr)
        raw_txn += mptr_read
        out_count = getCount(mptr_read)
        txn['out'] = []
        for index in range(out_count):
                out_list = []
                txn_out = {}
                mptr_read = mptr.read(8)
                raw_txn += mptr_read
                txn_out['satoshis'] = int(binascii.hexlify(mptr_read[::-1]), 16)
                out_list.append(txn_out['satoshis'])
                mptr_read = getCountBytes(mptr)
                raw_txn += mptr_read
                scriptpubkey_size = getCount(mptr_read)
                mptr_read = mptr.read(scriptpubkey_size)
                raw_txn += mptr_read
                txn_out['scriptpubkey'] = bytes.decode(binascii.hexlify(mptr_read))
                txn['out'].append(txn_out)
        if 'is_segwit' in txn and is_segwit == True:
                for index in range(input_count):
                        mptr_read = getCountBytes(mptr)
                        witness_count = getCount(mptr_read)
                        txn['input'][index]['witness'] = []
                        for inner_index in range(witness_count):
                                txn_witness = {}
                                mptr_read = getCountBytes(mptr)
                                witness_size = getCount(mptr_read)
                                txn_witness['witness'] = bytes.decode(binascii.hexlify(mptr.read(witness_size)))
                                txn['input'][index]['witness'].append(txn_witness)
        raw_txn += mptr.read(4)
        txn['txn_hash'] = getTxnHash(raw_txn)
        txn_id.add(txn['txn_hash'])

        inputs[txn['txn_hash']] = input_list

        for index in range(len(out_list)):
                out_id = "%s_%d" % (txn['txn_hash'], index)
                if out_id not in out:
                        out[out_id] = {}
                        out[out_id]['index'] = index
                out[out_id]['satoshis'] = out_list[index]

        print(json.dumps(txn, indent = 4))
        neo4j_import = os.path.join(os.path.sep, 'var', 'lib', 'neo4j', 'import')
        txn_node_path = os.path.join(neo4j_import, 'txn_node.csv')
        with open(txn_node_path, 'wt') as txn_file:
                print('name', file=txn_file)
                print('\n'.join(txn_id), file=txn_file)

        out_node_path = os.path.join(neo4j_import, 'out_node.csv')
        with open(out_node_path, 'wt') as out_file:
                out_list = [{'id': key, 'name': value['index'], 'satoshis': value['satoshis']} for key, value in out.items()]
                print('out_node: %s' % out_list)
                keys = out_list[0].keys()
                dict_writer = csv.DictWriter(out_file, keys)
                dict_writer.writeheader()
                dict_writer.writerows(out_list)

        txn_out_rel_path = os.path.join(neo4j_import, 'txn_out_rel.csv')
        with open(txn_out_rel_path, 'wt') as txn_out_file:
                txn_out_list = [{'from_node': 'transaction', 'from_key': key.split('_')[0], 'to_node': 'out', 'to_key': key} for key in out.keys()]
                print('txn_out_rel: %s' % txn_out_list)
                keys = txn_out_list[0].keys()
                dict_writer = csv.DictWriter(txn_out_file, keys)
                dict_writer.writeheader()
                dict_writer.writerows(txn_out_list)

        input_txn_rel_path = os.path.join(neo4j_import, 'input_txn_rel.csv')
        with open('input_txn_rel', 'wt') as out_txn_file:
                out_txn_list = [
                                {
                                'from_node': 'out',
                                'from_key': value, 
                                'satoshis': out[value]['satoshis'], 
                                'to_node': 'transaction', 
                                'to_key': txn['txn_hash']} for value in inputs[txn['txn_hash']]]
                print('input_txn_rel: %s' % out_txn_list)
                keys = out_txn_list[0].keys()
                dict_writer = csv.DictWriter(out_txn_file, keys)
                dict_writer.writeheader()
                dict_writer.writerows(out_txn_list)
        exit()

# node
        cypher = 'USING PERIODIC COMMIT '
        cypher += 'LOAD CSV WITH HEADERS FROM "file:///' +  + '" AS row '
        if 'source_reference' in columns:
                cypher += 'MERGE (n:' + node + ' { source_reference:row.source_reference })'
        else:
                cypher += 'MERGE (n:' + node + ' { name:row.name })'
        cypher += ' ON CREATE SET n = { ' + attribute_string + ' }'
        cypher += ' ON MATCH SET n += { ' + attribute_string + ' }'
        try:
                response = graph.run(cypher)
        except ProtocolError:
                raise CustomException({'error_message':'Unable to establish connection with Neo4j Bolt Server', 'host': os.getenv('NEXT_GEN_TOOLING_SERVER_HOSTNAME'), 'BOLT_PORT': int(os.getenv('BOLT_PORT'))}, 530)
        except ConstraintError as e:
                raise CustomException({'error_message':str(e)}, 545)

        resp_value = response.stats()
        # look at the stats() dictionary returned for all the queryable values in the response
        nodes_added = resp_value.get('labels_added')

## rel
#    cypher = 'USING PERIODIC COMMIT '
#    cypher += 'LOAD CSV WITH HEADERS FROM "file:///' + filename + '" AS row '
#    # let's match the from node first
#    if "glob_source" in dir(builtins):
#            cypher += 'MATCH (fn:' + from_node +":"+ builtins.glob_source + ' {' + from_attr + ':row.from_key}) '
#    else:
#            cypher += 'MATCH (fn:' + from_node + ' {' + from_attr + ':row.from_key}) '
#    # let's match the to node now
#    if "glob_source" in dir(builtins):
#            cypher += 'MATCH (tn:' + to_node +":"+ builtins.glob_source + ' {' + to_attr + ':row.to_key}) '
#    else:
#            cypher += 'MATCH (tn:' + to_node + ' {' + to_attr + ':row.to_key}) '
#
#    #todo Relationship direction ALWAYS goes (from_node)-[]->(to_node) - do we need a 'direction' passed in?
#    # let's setup the relationship creation (always use unique so relationships are not duplicated)
#    cypher += 'CREATE UNIQUE (fn)-[:' + relationship + ']->(tn)'
#    try:
#        response = graph.run(cypher)
#    except ProtocolError:
#        raise CustomException({'error_message':'Unable to establish connection with Neo4j Bolt Server', 'host': os.getenv('NEXT_GEN_TOOLING_SERVER_HOSTNAME'), 'BOLT_PORT': int(os.getenv('BOLT_PORT'))}, 530)
#    except ConstraintError:
#        raise CustomException({'error_message':str(e)}, 545)
#    logging.info(cypher)
#    resp_value = response.stats()
#    rels_added = resp_value.get('relationships_created')


#        check_raw_txn = rpc_connection.getrawtransaction(txn['txn_hash'])
#        print('checked raw txn = %s' % check_raw_txn)
#        print('txn_hash = %s' % txn['txn_hash'])
        return txn

def getBlock(mptr: mmap, start: int):
        block = {}
        mptr.seek(start + 88)
        txn_count = getTransactionCount(mptr)

        txn_list = []
        txn_list.append(getCoinbaseTransaction(mptr))
        for index in range(1, txn_count):
                txn = getTransaction(mptr)
                txn_list.append(txn)
        block['txn_list'] = txn_list
        return block
        

#def mmBlockFileParser(mptr: mmap):
#        block_file = []
#        mptr.seek(0)
#        try:
#                while True:
#                        start = mptr.tell()
#                        block_file.append(getBlock(mptr, start))
#        except ValueError or EOFError:
#                pass
#        print(json.dumps(block_file, indent=4))
#
#if __name__ == '__main__':
#        mm = loadBlockFilesInMemory(0)
#        mmBlockFileParser(mm)
#        mm.close()

def blockFileParser(index: int):
        block_file = os.path.join(blocks_dir, 'blk%05d.dat' % index)
        with open(block_file, 'rb') as latest_block_file:
                # load file to memory
                mptr = mmap.mmap(latest_block_file.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only

                block_file = []
                try:
                        while True:
                                logging.debug(index)
                                start = mptr.tell()
                                block_file.append(getBlock(mptr, start))
                except ValueError or EOFError:
                        pass
#                        print(json.dumps(block_file, indent=4))
                mptr.close()
                del block_file

if __name__ == '__main__':
        for index in range(1234):
                blockFileParser(index)
                gc.collect()
        end_time = str(datetime.datetime.now())
        logging.debug(start_time)
        logging.debug(end_time)


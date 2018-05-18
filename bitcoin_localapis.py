import hashlib
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
#import json
import simplejson as json
import binascii
import base58
import ecdsa
from pycoin.ecdsa.numbertheory import modular_sqrt
import pycoin
import pandas as pd
import sys
import datetime
import os
import glob

myaddress = input('Enter Bitcoin Address: ')

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('alice', 'passw0rd'))

SANTOSIS_IN_BTC = 10**8

# Every Block Height at which Block Reward becomes Half
BLOCK_REWARD_HALVING = 210000
BLOCK_REWARD_1 = 50 * SANTOSIS_IN_BTC

N_TIME_1 = 1231006505

def getCurrentBlockReward():
    block_height = getCurrentBlockHeight()
    block_halving_count = int(block_height / BLOCK_REWARD_HALVING)
    current_block_reward = BLOCK_REWARD_1 / (2 ** block_halving_count)
    return current_block_reward

def getCurrentBitcoinInCirculation():
    block_height = getCurrentBlockHeight()
    block_halving_count = int(block_height / BLOCK_REWARD_HALVING)
    block_reward = BLOCK_REWARD_1 / SANTOSIS_IN_BTC
    bitcoin_in_circulation = 0
    for block_halfing_index in range(block_halving_count):
        bitcoin_in_circulation += (BLOCK_REWARD_HALVING * block_reward)
        block_reward = block_reward / 2
    bitcoin_in_circulation += (block_height % BLOCK_REWARD_HALVING) * block_reward
    return bitcoin_in_circulation

def getBitcoinCirculationLimit():
    block_reward = BLOCK_REWARD_1 / SANTOSIS_IN_BTC
    bitcoin_in_circulation = 0
    while block_reward != round(block_reward / 2, 8):
        bitcoin_in_circulation += (BLOCK_REWARD_HALVING * block_reward)
        block_reward = block_reward / 2
    return bitcoin_in_circulation

def getDateToReachLimit():
    block_reward = BLOCK_REWARD_1 / SANTOSIS_IN_BTC
    block_halving_count = 0
    while round(block_reward, 8) != round(block_reward / 2, 8):
        block_halving_count += 1
        block_reward = block_reward / 2
    sec_to_mine_zero_reward_block = 10 * BLOCK_REWARD_HALVING * block_halving_count * 60
    unix_sec = N_TIME_1 + sec_to_mine_zero_reward_block
    time_of_zero_reward_block = datetime.datetime.fromtimestamp(unix_sec).strftime('%Y-%m-%d %H:%M:%S')
    return time_of_zero_reward_block

def getCurrentBlockchainSizeInGB():
    blockchain_size = sum(os.path.getsize(f) for f in glob.glob(os.path.join(os.getenv('HOME'),'.bitcoin', 'blocks', 'blk0*.dat')))
    return blockchain_size / (2 ** 30)

def hash2LittleEndian2LittleEndian(a:str, b:str):
     # Reverse inputs before and after hashing due to big-endian / little-endian nonsense
     a1 = binascii.unhexlify(a)[::-1]
     b1 = binascii.unhexlify(b)[::-1]
     h = hashlib.sha256(hashlib.sha256(a1 + b1).digest()).digest() 
     return binascii.hexlify(h[::-1])

def hashBigEndian2LittleEndian(a: str):
     h = hashlib.sha256(hashlib.sha256(bytes.fromhex(a)).digest()).digest() 
     return binascii.hexlify(h[::-1])

def build_merkle_root(hash_list: list):
        if len(hash_list) < 2:
            return hash_list[0]
        new_hash_list = []
 
        # Process pairs. For odd length, the last is skipped
        for i in range(0, len(hash_list) - 1, 2):
            new_hash_list.append(hash2LittleEndian2LittleEndian(hash_list[i], hash_list[i + 1]))
 
        # odd, hash last item twice
        if len(hash_list) % 2 == 1:
            new_hash_list.append(hash2LittleEndian2LittleEndian(hash_list[-1], hash_list[-1]))
 
        return build_merkle_root(new_hash_list)

def getTransactionHashFromHex(txn_hex: str):
        hashval = hashBigEndian2LittleEndian(txn_hex)
        return hashval

#The nBits field in the block header encodes a 256-bit unsigned integer
#called the target threshold using a base 256 version of the scientific notation.
#Let b1 b2 b3 b4 be the four bytes in nBits. The first byte b1 plays the role of
#the exponent and the remaining three bytes encode the mantissa. The target
#threshold T is derived as
#T = b2b3b4 × 256**(b1−3),
#where b1 and b2 b3 b4 are interpreted as unsigned integers.
def getTargetThreshold(hex_bits: bytes):
        shift = '0x%s' % hex_bits[0:2]
        shift_int = int(shift, 16)
        value = '0x%s' % hex_bits[2:]
        value_int = int(value, 16)
        target = value_int * 2 ** (8 * (shift_int - 3))
        hex_target = hex(target)
        return hex_target

def getAllTxnsInBlock(block: dict):
        txns = block['tx']
        return txns

def getCurrentBlockHeight():
        current_block_height = rpc_connection.getblockcount()
        return current_block_height

def getBlockHash(block_height: int):
        block_hash = rpc_connection.getblockhash(block_height)
        return block_hash

def getBlockHeaderFromHeightInHex(block_height: int):
        block_hash = getBlockHash(block_height)
        block_header_in_hex = rpc_connection.getblockheader(block_hash, False)
        return block_header_in_hex

def getBlock(block_height: int):
        block_hash = getBlockHash(block_height)
        block = rpc_connection.getblock(block_hash)
        return block

def getBlockInHex(block_height: int):
        block_hash = getBlockHash(block_height)
        block = rpc_connection.getblock(block_hash, False)
        return block

def getBlockSizeInKB(block_height: int):
        block_size = len(getBlockInHex(block_height))
        block_size_kb = (block_size >> 10) >> 1
        return block_size_kb

def getTxnCountInBlock(block_height: int):
        block_hex = getBlockInHex(block_height)
        indicator = int(block_hex[160:162], 16)

        if indicator < 0xfd:
                txn_count_str = block_hex[162:164]
        elif indicator == 0xfd:
                txn_count_str = block_hex[162:166]
        elif indicator == 0xfe:
                txn_count_str = block_hex[162:170]
        else:
                txn_count_str = block_hex[162:178]

        txn_count = int(bytes.decode(binascii.hexlify(binascii.unhexlify(txn_count_str)[::-1])), 16)
        return txn_count

def getAvgTxnRate(start_block_height: int, end_block_height: int):
        total_txn_count = 0
        for block_height in range(start_block_height, end_block_height):
                txn_count = getTxnCountInBlock(block_height)
                total_txn_count += txn_count
        secs = (end_block_height - start_block_height) * 10 * 60
        avg_txn_rate = total_txn_count / secs
        return avg_txn_rate

def getAvgTxnRateInLast24Hrs():
        blocks_in_a_day = 6 * 24
        end_block_height = getCurrentBlockHeight()
        start_block_height = current_block_height - blocks_in_a_day
        avg_txn_rate = getAvgTxnRate(start_block_height, end_block_height)
        return avg_txn_rate

def getAvgTxnRateInLastMonth():
        block_count = 6 * 24 * 30
        end_block_height = getCurrentBlockHeight()
        start_block_height = current_block_height - block_count
        avg_txn_rate = getAvgTxnRate(start_block_height, end_block_height)
        return avg_txn_rate

CURRENT_BLOCK_REWARD = 12.5

def getBlockReward(block_height: int):
        block = getBlock(block_height)
        for txn_hash in getAllTxnsInBlock(block):
                block_reward = 0.0
                txn = getTransactionFromHash(txn_hash)
                block_reward_is_set = False
                block_reward = 0.0
                for vin in txn['vin']:
                        if 'coinbase' in vin:
                                block_reward_is_set = True
                                for vout in txn['vout']:
                                        block_reward += float(vout['value'])
                        if block_reward_is_set == True:
                                break
                if block_reward_is_set == True:
                        break
        return block_reward

def totalTransactionFeeInBlock(block_height: int):
        block_reward = getBlockReward(block_height)
        txn_fee_collected_per_block = block_reward - (50 * float(1 / (2 ** int(block_height / 210000))))
        return txn_fee_collected_per_block

def getNetworkHashRate(block_height: int):
        block = getBlock(block_height)
        target_threshold = int(getTargetThreshold(block['bits']), 16)
        network_hashrate = (2 ** 256) / ((target_threshold + 1) * 600)
        return network_hashrate

#
TARGET_THRESHOLD_1 = 0x00ffff * (256 ** 26)

def getDifficulty(block_height: int):
        block = getBlock(block_height)
        target_threshold = int(getTargetThreshold(block['bits']), 16)
        difficulty = TARGET_THRESHOLD_1 / target_threshold

        return difficulty

TARGET_DIFFICULTY_SET_EVERY = 2016

#T_new = (T_old × Measured duration for finding 2,016 blocks in seconds) / (2016 × 600)
def calculateNextTargetThreashold(block_height: int):
        # no change in target threshold
        if (block_height + 1) % 2016 != 0:
                block = getBlock(block_height)
                target_threshold = int(getTargetThreshold(block['bits']), 16)
                return target_threshold

        n =  (block_height + 1) / 2016
        b1 = 2016 * (n - 1)
        b2 = 2016 * n - 1
        block_t1 = getBlock(b1)
        block_t2 = getBlock(b2)
        t1 = block_t1['time']
        t2 = block_t2['time']
        target_threshold_old = int(getTargetThreshold(block_t2['bits']), 16)
        time_diff = t2 - t1
        target_threshold_new = (target_threshold_old * time_diff) / (2016 * 600)
        return target_threshold_new

def getUnspentList(address: str):
        unspent_list = rpc_connection.listunspent(1, 9999999, ["%s" % (address)] , True, {})
        return unspent_list


def getBalanceInBTCOnAddress(address: str):
        unspent_list = rpc_connection.listunspent(1, 9999999, ["%s" % (address)] , True, {})
        amount = 0
        for unspent_txn in unspent_list:
                amount += unspent_txn['amount']
        return amount

def getTransactionFromHash(txn_hash: str):
        raw_txn = rpc_connection.getrawtransaction(txn_hash)
        txn_dict = rpc_connection.decoderawtransaction(raw_txn)
        return txn_dict

def getTransactionHexFromHash(txn_hash: str):
        raw_txn = rpc_connection.getrawtransaction(txn_hash)
        return raw_txn

def getHash160FromAddress(address: str):
        hash160_of_addr = bytes.decode(binascii.hexlify(base58.b58decode_check(address)))[2:]
        return hash160_of_addr

def getAddressFromHash160(hash160_val: bytes):
        address = base58.b58encode_check(bytes.fromhex('00') + hash160_val)
        return address

###
# Below bytes Block header, Number of Transactions and Transaction information are in sequence in Raw Block
###
##
# Bytes before header
##
#f9 be b4 d9 Magic ID
#6b 39 0b 00 Block length
##
# Block Header
##
#00 00 00 20 Version 4 bytes
#cd 81 17 54 2b 14 ee f8 4b 42 80 f4 d6 60 fa e6 cb b0 4a 87 4e 38 44 00 00 00 00 00 00 00 00 00 Previous Block Hash 32 bytes
#5b ff 72 ea 1e 2a 11 26 a6 49 88 7c 3e 98 f9 cd a6 8f d6 e1 43 15 ae bf 60 3a db e4 e9 a3 66 a6 Merkle Tree Root 32 bytes
#27 43 b3 5a Timestamp 4 bytes
#49 4a 51 17 Bits 4 bytes
#12 31 49 14 Nounce 4 bytes

##
# Number of Transactions
##
#fd (less than 0xfd is 1 byte, 0xfd is 2 bytes, 0xfe is 4 bytes, 0xff is 8 bytes)
#ab 03 Number of Transactions (939)

##
# Most Common Raw Transaction Format Pre-SegWit (All values are in Big Endian)
##
#01 00 00 00 version (1)
#01 number of inputs
#7f 95 0a b7 90 83 8e 0c 05 e7 98 56 d2 5d 58 68 23 fe 13 9e 18 07 40 5a 3f 20 7f f3 3f 9b 76 63 previous tx hash
#01 00 00 00 
#6b script length (107 bytes)
#48 sig length (72 bytes)
#30 der
#45 length of sig ECDSA (69)
#02 int type
#21 length of R (33 bytes)
#00 d8 62 94 03 cd 3b 49 95 0d a9 29 36 53 c6 27 91 49 c0 29 e6 b7 b1 53 71 34 2d 0d 2c e2 86 c8 f2 (R)
#02 int type
#20 length of S (32 bytes)
#78 78 79 85 a6 44 e9 4f d9 24 6f 6c 25 73 33 36 c9 4a f5 f0 0d 9d 34 a0 7d c2 f9 e0 98 7e f9 90 
#01 SIGHASH_ALL
#21 length of pubkey (33 bytes)
#02 public key type (0x2 is compressed pubkey(x) with even y, 0x3 is compressed pubkey(x) with odd y, 0x4 full pubkey)
#b7 26 d7 ea e1 1a 6d 5c f3 b2 36 2e 77 3e 11 6a 61 40 34 7d ce e1 b2 94 3f 4a 28 97 35 1e 5d 90 (pubkey)
#ff ff ff ff Sequence
#02 number of outputs
#1b f0 3c 00 00 00 00 00 Value (3993627 santoshi)
#17 lenght of scriptPubKey (23 bytes)
#a9 OP_HASH160
#14 Hash size (20 which is 160 bits)
#69 f3 75 73 80 a5 68 20 ab c7 05 28 67 21 65 99 e5 75 cd dd Hash160
#87 OP_EQUAL
#77 c1 ca 1c 00 00 00 00 Value ()
#19 length of scriptPubKey (25 bytes)
#76 OP_DUP
#a9 OP_HASH160
#14 Hash size (20)
#d5 f9 50 ab e0 b5 59 b2 b7 a7 ab 3d 18 a5 07 ea 1c 3e 4a c6 Hash160
#88 OP_EQUALVERIFY
#ac OP_CHECKSIG
#00 00 00 00 Lock time

transaction_output_struct = {"nValue": "8 bytes", "scriptPubkeyLen" : "1-9 bytes", "scriptPubkey" : "script"}

transaction_output_list = []

sig_type_struct_der = {"nInput": "Length of proceeding Input bytes", "isInteger" : "0x02 indicating integer", "nIntegerR" : "1 byte (Length of R)", "R" : "32 bytes", "nIntegerS" : "1 bytes (Length of S)", "S" : "32 bytes", "flagSIGHASH" : "0x01 for ALL, 0x02 for None, 0x03 for SINGLE, 0x81 for ALL|ANYONECANPAY, 0x82 for NONE|ANYONECANPAY, 0x83 for SINGLE|ANYONECANPAY"}

sig_type_struct = {} # this could be sig_struct_der or something else

sig_struct = {"nSig" : "1 byte length of sig", "typeSig" : "1 byte code (0x30 for DER)", "actualSig" : sig_type_struct}

pubkey_struct = {}

script_sig_struct = {"sig" : sig_struct, "pubkey" : pubkey_struct}

transaction_input_struct = {"hash" : "32 bytes", "outIndex" : "4 bytes", "scriptSigLen" : "1-9 bytes", "scriptSig" : script_sig_struct, "nSequence" : "4 bytes"}

transaction_input_list = []

transaction_struct = {"nVersion" : "4 bytes", "nInputs" : "1-9 bytes", "inputList": transaction_input_list, "nOutputs" : "1-9 bytes", "outputList" : transaction_input_list, "nLockTime" : "4 bytes"}

block_transaction_list = []

block_header_struct = {"nVersion" : "4 bytes", "hashPrevBlock" : "32 bytes", "hashMerkleRoot" : "32 bytes", "nTime" : "4 bytes", "nBits" : "4 bytes", "nNounce" : "4 bytes"}

block_struct = {"blockHeader": block_header_struct, "transactionList": block_transaction_list}

#def decodeBlock(block_hash: str, False):
        

def getNetworkFees(txn_hash: str):
        txn = getTransactionFromHash(txn_hash)
        print("Debug:: txn = %s" % (txn))
        print("Debug:: txn['vin'] = %s" % (txn['vin']))
        hash_address_map = {}
        for input_txn in txn['vin']:
                print("Debug:: input_txn = %s" % (input_txn))
                if 'txid' in input_txn:
                        print("Debug:: input_txn['txid'] = %s" % (input_txn['txid']))
                        if 'txinwitness' in input_txn:
                                input_pubkey = input_txn['txinwitness'][1]
                                input_address = pubkeyToAddress(input_pubkey)
                                print("Address = %s from Public Key = %s" % (input_address, input_pubkey))
                                hash_address_map[input_txn['txid']] = input_address
                        else:
                                asm = input_txn['scriptSig']['asm'].split(" ")
                                if asm[-2][-5] == '[ALL]':
                                        hash_address_map[input_txn['txid']] = ""
                                else:
                                        input_pubkey = asm[-1]
                                        input_address = pubkeyToAddress(input_pubkey)
                                        print("Address = %s from Public Key = %s" % (input_address, input_pubkey))
                                        hash_address_map[input_txn['txid']] = input_address

        if len(hash_address_map) == 0:
                network_fees = 0
                print("CoinBase Network Fees = %d" % (network_fees))
                return network_fees

        out_value = 0
        for out_txn in txn['vout']:
                out_value += out_txn['value']
                print("Out Value = %.8f" % (out_txn['value']))

        input_value = 0
        input_addr_count = 0
        for input_txn_id in hash_address_map.keys():
                txn = getTransactionFromHash(input_txn_id)
                vout_list = []
                for vin in txn['vin']:
                        vout_list.append(vin['vout'])
                for vout in txn['vout']:
                        if vout['scriptPubKey']['type'] == 'pubkeyhash':
                                vout_index = vout['scriptPubKey']['addresses']
                                if hash_address_map[input_txn_id] == "" or hash_address_map[input_txn_id] in vout_index:
                                        input_addr_count += 1
                                        input_value += vout['value']
                                        print("Input Value = %.8f" % (vout['value']))
        network_fees = input_value - out_value
        if input_addr_count == 0:
                sys.exit()
        return network_fees

def getTotalNetworkFeesInBlock(block_height: int):
        block = getBlock(block_height)
        sum_of_network_fees = 0
        for txn_hash in block['tx']:
                network_fees = getNetworkFees(txn_hash)
                print("network_fees = %.8f" % (network_fees))
                sum_of_network_fees += network_fees
        return sum_of_network_fees

#def getTotalNetworkFeesForAddress(address: str):


def double_sha256d(bstr):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def convertPKHToAddress(prefix, addr):
    data = prefix + addr
    return base58.b58encode(data + double_sha256d(data)[:4])

def pubkeyToAddress(pubkey_hex):
        pubkey = bytearray.fromhex(pubkey_hex)
        round1 = hashlib.sha256(pubkey).digest()
        h = hashlib.new('ripemd160')
        h.update(round1)
        pubkey_hash = h.digest()
        return convertPKHToAddress(b'\x00', pubkey_hash)

def sigcheck(sig: str, pubkey: str, raw_txn: str):
        hashval = binascii.hexlify(hashlib.sha256(bytes.fromhex(raw_txn)).digest())
        print("hash val = %s" % (hashval))
        txn_sha256 = bytes.decode(hashval)
        print("txn_sha256 = %s" % (txn_sha256))

        prefix = pubkey[0:2]
        if prefix == "02" or prefix == "03":
                pubkey = getFullPubKeyFromCompressed(pubkey)[2:]
        elif prefix == "04":
                pubkey = pubkey[2:]

        print("full public key = %s" % pubkey)
        sig_b = bytes.fromhex(sig)
        txn_sha256_b = bytes.fromhex(txn_sha256)
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=ecdsa.SECP256k1)
        if vk.verify(sig_b, txn_sha256_b, hashlib.sha256) == True: # True
                print("Signature is Valid")
        else:
                print("Signature is not Valid")

#def generatePrivKey():
        

#def privkeyToPubkey():
#
#def signTransactionWithPrivKey():

def getFullPubKeyFromCompressed(x_str: str):
        prefix = x_str[0:2]
        print("prefix = %s" % (prefix))
        x_str = x_str[2:]
        x = int(x_str, 16)
        print("x = \t\t%x" % (x))
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_squared = (x**3 + 7) % p
        y = modular_sqrt(y_squared, p)
        y_str = "%x" % y
        print("y_str before = \t%s" % (y_str))
        y_is_even = (int(y_str[-1], 16) % 2 == 0)
        if prefix == "02" and y_is_even == False or prefix == "03" and y_is_even == True:
                y = p - y
                y_str = "%x" % y
        if len(y_str) % 2 == 1:
                y_str = "0" + y_str
        print("y_str after = \t%s" % (y_str))
        return "04" + x_str + y_str

if __name__ == '__main__':
        current_block_height = getCurrentBlockHeight()
        print("Current Block Height = %d" % (current_block_height))

        current_block_reward = getCurrentBlockReward()
        print("Current Block Reward in BTC = %.8f" % (current_block_reward / SANTOSIS_IN_BTC))

        current_bitcoin_in_circulation = getCurrentBitcoinInCirculation()
        print("Current Bitcoin In Circulation = %d" % current_bitcoin_in_circulation)

        bitcoin_circulation_limit = getBitcoinCirculationLimit()
        print("Bitcoin Circulation Limit = %d" % bitcoin_circulation_limit)

        time_of_zero_reward_block = getDateToReachLimit()
        print("Time of Zero Reward block = %s" % time_of_zero_reward_block)

        blockchain_size = getCurrentBlockchainSizeInGB()
        print("Blockchain Size in GB = %d" % blockchain_size)

        current_block_hash = getBlockHash(current_block_height)
        print("Block Header Hash = %x for Block Height = %d" % (int(current_block_hash, 16), current_block_height))

        block_header_in_hex = getBlockHeaderFromHeightInHex(current_block_height)
        print("Block Header = %s for Block Height = %d" % (block_header_in_hex, current_block_height))

        header_hash = hashBigEndian2LittleEndian(block_header_in_hex)
        print("Block Header Hash = %s for Block Header in HEX = %s" % (header_hash, block_header_in_hex))

        block = getBlock(current_block_height)
        print("Block = %s for Block Height = %d" % (json.dumps(block), current_block_height))

        network_hash_rate = getNetworkHashRate(current_block_height)
        print("Network Hash Rate = %d" % network_hash_rate)
#        index = 0
#        for txn in block['tx']:
#                print("txn[%d] = %s" % (index, txn))
#                index += 1
        merkel_tree_root = build_merkle_root(block['tx'])
        print("Calculated Merkel Tree Root = %s" % (merkel_tree_root))
        print("Actual Merkel Tree Root = %s" % (block['merkleroot']))

        target_threshold = getTargetThreshold(block['bits'])
        print("Target Threshold = %s" % (target_threshold))

        unspent_list = getUnspentList(myaddress)
        print ("Unspent Transaction List = %s" % (unspent_list))

        balance_in_bitcoin = getBalanceInBTCOnAddress(myaddress)
        print ("Balance In BTC = %.8f for Address = %s" % (balance_in_bitcoin, myaddress))

        txn_hash = block['tx'][0]
        print("Transaction Hash = %s" % (txn_hash))

        txn = getTransactionFromHash(txn_hash)
        print("Transaction = %s" % (json.dumps(txn)))

        txn_hex = getTransactionHexFromHash(txn_hash)
        print("Raw Transaction = %s" % (txn_hex))

        txn_hash = getTransactionHashFromHex(txn_hex)
        print("Transaction Hash = %s" % (txn_hash))

#        txn_hash = '751dae89a9db47790997455c5587bbb22ee6ac8acb046cff1a78400daabbe5a5'
#        network_fees_in_btc = getNetworkFees(txn_hash)
#        print("Network Fees in BTC = %.8f" % (network_fees_in_btc))

#        pubkey = "03d7b3bc2d0b4b72a845c469c9fee3c8cf475a2f237e379d7f75a4f463f7bd6ebd"
#        print("Address: %s from pubkey = %s" % (pubkeyToAddress(pubkey), pubkey))

#        network_fees_in_btc = getTotalNetworkFeesInBlock(current_block_height)
#        print("Combined Network Fees = %.8f for Block Height = %d" % (network_fees_in_btc, current_block_height))

        sig = "d8629403cd3b49950da9293653c6279149c029e6b7b15371342d0d2ce286c8f278787985a644e94fd9246f6c25733336c94af5f00d9d34a07dc2f9e0987ef990"
        pubkey = "02b726d7eae11a6d5cf3b2362e773e116a6140347dcee1b2943f4a2897351e5d90"
        address = pubkeyToAddress(pubkey)
        print("****Address = %s from pubkey = %s" % (address, pubkey))
        full_raw_txn = "01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207ff33f9b7663010000006b483045022100d8629403cd3b49950da9293653c6279149c029e6b7b15371342d0d2ce286c8f2022078787985a644e94fd9246f6c25733336c94af5f00d9d34a07dc2f9e0987ef990012102b726d7eae11a6d5cf3b2362e773e116a6140347dcee1b2943f4a2897351e5d90ffffffff021bf03c000000000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c000000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac00000000"
        raw_txn = "01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207ff33f9b7663010000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688acffffffff021bf03c000000000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c000000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac0000000001000000"
        sigcheck(sig, pubkey, raw_txn)
#        raw_txn_with_full_pubkey = "01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207ff33f9b7663010000001976a914514b4af293b8b71a7d00f342f6ef0fb17b2d761c88acffffffff021bf03c000000000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c000000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac0000000001000000"
#        sigcheck(sig, pubkey, raw_txn_with_full_pubkey)

        compressed_pubkey = "025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec"
        full_pubkey = getFullPubKeyFromCompressed(compressed_pubkey)
        print("Full Public Key = %s from Compressed Public Key = %s" % (full_pubkey, compressed_pubkey))

        block_reward = getBlockReward(current_block_height)
        print("Block Reward = %.8f" % (block_reward))

        txn_fees_per_block = totalTransactionFeeInBlock(current_block_height)
        print("Transaction Fee Collected in current block = %.8f" % (txn_fees_per_block))

        next_difficulty = getDifficulty(current_block_height)
        print("Next Difficulty = %d" % (next_difficulty))

        hash160_of_addr = getHash160FromAddress(myaddress)
        print ("Hash 160 = %s from Address = %s" % (hash160_of_addr, myaddress))

        hash160_val = bytes.fromhex(hash160_of_addr)
        address = getAddressFromHash160(hash160_val)
        print("Address = %s from Hash160 String = %s" % (address, hash160_of_addr))

        txn_count = getTxnCountInBlock(current_block_height)
        print("Transaction Count = %d in Block = %d" % (txn_count, current_block_height))

#        txn_rate = getAvgTxnRateInLast24Hrs()
#        print("Average Transaction Rate in Last 24 Hrs = %.2f" % (txn_rate))

        block_size_in_kb = getBlockSizeInKB(current_block_height)
        print("Block Size in KB = %d for Block = %d" % (block_size_in_kb, current_block_height))
#        d = {}
#        for block_height in range(120000, current_block_height, 10000):
#                txn_fees_per_block = totalTransactionFeeInBlock(block_height)
##                d['Block Height'] = block_height
##                d['Transaction Fees'] = txn_fees_per_block
#                d[block_height] = txn_fees_per_block
#                print("Txn Fee Collection = %.8f in Block = %d" % (txn_fees_per_block, block_height))
##        df = pd.DataFrame(d, index=[0])
##        df.plot.bar()

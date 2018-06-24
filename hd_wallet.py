import hashlib
import mnemonic_code
import hmac
import pbkdf2
import binascii
import optparse
import sys
from bitcoin_secp256k1 import BitcoinSec256k1
from base58 import base58_decode, base58_encode

# implementation of BIP32
# mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF

def hash160(secret: bytes):
        secrethash = hashlib.sha256(secret).digest()
        h = hashlib.new('ripemd160')
        h.update(secrethash)
        secret_hash160 = h.digest()
        return secret_hash160

def generateSeedFromStr(code: str, salt: str):
        seed = pbkdf2.pbkdf2(hashlib.sha512, code, salt, 2048, 64)
#        seed = pbkdf2.pbkdf2(hashlib.sha256, code, salt, 50000, 64)
        print('seed = %s' % bytes.decode(binascii.hexlify(seed)))
        return seed

def generateMasterKeys(seed: bytes):
        h = hmac.new(bytes("Bitcoin seed", 'utf-8'),seed, hashlib.sha512).digest()
        private_key = int(binascii.hexlify(h[0:32]), 16)
        chaincode = h[32:64]
        return private_key, chaincode

#def base58_encode(num):
#        """ Returns num in a base58-encoded string """
#        alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
#        base_count = len(alphabet)
#        encode = ''
#        
#        if (num < 0):
#                return ''
#        
#        while (num >= base_count):      
#                mod = num % base_count
#                encode = alphabet[mod] + encode
#                num = num // base_count
#
#        if (num):
#                encode = alphabet[num] + encode
#
#        return encode

def encodedSerializationKeys(key: int, chaincode: bytes, depth: int, is_private: bool, is_mainnet: bool, child_index=0, parent_key=0):
        if is_private == True:
                if is_mainnet == True:
                        version = b'\x04\x88\xAD\xE4'
                else:
                        version = b'\x04\x35\x83\x94'
        else:
                if is_mainnet == True:
                        version = b'\x04\x88\xB2\x1E'
                else:
                        version = b'\x04\x35\x87\xCF'
        if depth == 0:
                # for root key
                parent_fingerprint = b'\x00\x00\x00\x00'
        else:
                parent_fingerprint = hash160(binascii.unhexlify('%064x' % parent_key))[0:4]

        key_b = b'\x00' + binascii.unhexlify('%064x' % key)
        child_number = binascii.unhexlify('%08x' % child_index)                
        serialized_key = version + bytes([depth]) + parent_fingerprint + child_number + chaincode + key_b
        print('serialized key = %s' % bytes.decode(binascii.hexlify(serialized_key)))
        h = hashlib.sha256(hashlib.sha256(serialized_key).digest()).digest()
        print('hash = %s' % bytes.decode(binascii.hexlify(h)))
        serialized_key_with_checksum = int(binascii.hexlify(serialized_key + h[0:4]), 16)
        print('with checksum: %x' % serialized_key_with_checksum)
        encoded_serialized_key = base58_encode(serialized_key_with_checksum)

        return encoded_serialized_key

def generateChildAtIndex(privkey: int, chaincode: bytes, index: int):
        global N
        if index >= (1<<31):
                # hardened
                print('hardened')
                h = hmac.new(chaincode, b'\x00' + binascii.unhexlify('%064x' % privkey) + binascii.unhexlify('%08x' % index), hashlib.sha512).digest()
                print('child seed = %s' % bytes.decode(binascii.hexlify(b'\x00' + binascii.unhexlify('%064x' % privkey) + binascii.unhexlify('%08x' % index))))
                print('h = %s' % bytes.decode(binascii.hexlify(h)))
        else:
                # normal
                bitcoin_sec256k1 = BitcoinSec256k1()
                pubkey = bitcoin_sec256k1.privkey2pubkey(privkey, True)
                print('pubkey = %s' % bytes.decode(binascii.hexlify(pubkey)))
                h = hmac.new(chaincode, pubkey + binascii.unhexlify('%08x' % index), hashlib.sha512).digest()
        childprivkey = (int(binascii.hexlify(h[0:32]), 16) + privkey) % N
        print('h[0:32] = %x' % int(binascii.hexlify(h[0:32]), 16))
        print('privkey = %x' % privkey)
        child_chaincode = h[32:64]
        return childprivkey, child_chaincode

if __name__ == '__main__':
        parser = optparse.OptionParser(usage="python3 hd_wallet.py -s <Salt>")
        parser.add_option('-s', '--salt', action='store', dest='salt', help='Add salt to secret')
        (args, _) = parser.parse_args()
        if args.salt == None:
                print ("Missing required argument")
                sys.exit(1)

        mnemonic_code = mnemonic_code.getMnemonicWordCodeString()
        print('mnemonic code: %s' % mnemonic_code)
        seed = generateSeedFromStr(mnemonic_code, "mnemonic" + args.salt)

        master_privkey, master_chaincode = generateMasterKeys(seed)

        if master_privkey == 0 or master_privkey >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F:
                print('invalid master key')

        print('master private key = %x, master chaincode = %s' % (master_privkey, bytes.decode(binascii.hexlify(master_chaincode))))
        encoded_serialized_key = encodedSerializationKeys(master_privkey, master_chaincode, 0, True, True)
        print('Encoded Serialized Key = %s' % encoded_serialized_key)

        # for hardened
        child_privkey, child_chaincode = generateChildAtIndex(master_privkey, master_chaincode, 1<<31)
        print('child private key = %x, child chaincode = %s' % (child_privkey, bytes.decode(binascii.hexlify(child_chaincode))))

        # for normal
        child_privkey, child_chaincode = generateChildAtIndex(master_privkey, master_chaincode, 0)
        print('child private key = %x, child chaincode = %s' % (child_privkey, bytes.decode(binascii.hexlify(child_chaincode))))

import hashlib
import mnemonic_code
import hmac
import pbkdf2
import binascii
import optparse
import sys

# implementation of BIP32
# mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private

def generateSeedFromStr(code: str, salt: str):
        seed = pbkdf2.pbkdf2(hashlib.sha512, code, salt, 2048, 64)
#        seed = pbkdf2.pbkdf2(hashlib.sha256, code, salt, 50000, 64)
        print('seed = %s' % bytes.decode(binascii.hexlify(seed)))
        return seed

def generateMasterKeys(seed: bytes):
        h = hmac.new(bytes("Bitcoin seed", 'utf-8'),seed, hashlib.sha512).digest()
        private_key = h[0:32]
        chaincode = h[32:64]
        return private_key, chaincode

def serializationKeys():
        pass

def privkey2pubkey(privkey: int):
        pass

def generateHardenedChildAtIndex(privkey: int, chaincode: int, index: int):
        pubkey = privkey2pubkey(privkey)
        privkey, chaincode = generateChildKey(chaincode, privkey2pubkey(privkey)+ bytes([index]))
        return privkey, chaincode

def generateNormalChildAtIndex(pubkey: int, chaincode: int, index: int):
        pubkey = privkey2pubkey(privkey)
        privkey, chaincode = generateChildKeys(chaincode, privkey2pubkey(privkey)+ bytes([index]))
        return privkey, chaincode

def generateChildAtIndex():
        pass

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

        master_private_key, master_chaincode = generateMasterKeys(seed)

        if int(binascii.hexlify(master_private_key), 16) == 0 or int(binascii.hexlify(master_private_key), 16) >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F:
                print('invalid master key')

        print('master private key = %s, master chaincode = %s' % (bytes.decode(binascii.hexlify(master_private_key)), bytes.decode(binascii.hexlify(master_chaincode))))

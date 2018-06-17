import hashlib
import mnemonic_code
import hmac
import pbkdf2
import binascii
import optparse

def generateSeedFromStr(code: str, salt: str):
        seed = pbkdf2.pbkdf2(hashlib.sha512, code, salt, 2048, 64)
        print('seed = %s' % bytes.decode(binascii.hexlify(seed)))
        return seed

def generatePrivateKey(seed: bytes, code: str):
        h = hmac.new(seed, code.encode('utf-8'), hashlib.sha512).digest()
        private_key = h[0:32]
        chaincode = h[32:64]
        return private_key, chaincode

# K = k * G
def getPubkeyFromPrivkey(private_key: bytes):
        pass

if __name__ == '__main__':
        parser = optparse.OptionParser(usage="python3 hd_wallet.py -s <Salt>")
        parser.add_option('-s', '--salt', action='store', dest='salt', help='Add salt to secret')
        (args, _) = parser.parse_args()
        if args.salt == None:
                logging.error ("Missing required argument")
                sys.exit(1)

        mnemonic_code = mnemonic_code.getMnemonicWordCodeString()
        seed = generateSeedFromStr(mnemonic_code, args.salt)

        private_key, chaincode = generatePrivateKey(seed, mnemonic_code)

        print('privake key = %s' % bytes.decode(binascii.hexlify(private_key)))

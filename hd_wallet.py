import hashlib
import mnemonic_code
import hmac
import pbkdf2
import binascii

def generate_seed_from_str(code: str, seed: str):
        seed = pbkdf2.pbkdf2(hashlib.sha512, code, seed, 2048, 64)
        print('seed = %s' % bytes.decode(binascii.hexlify(seed)))
        return seed

if __name__ == '__main__':
        mnemonic_code = mnemonic_code.getMnemonicWordCodeString()
        generate_seed_from_str(mnemonic_code, 'testnewseed')

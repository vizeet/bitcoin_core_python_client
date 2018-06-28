import hashlib
import binascii
import bitcoin_base58

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()


def privkey2wif(privkey: bytes, is_testnet: bool):
        wif_privkey = bitcoin_base58.forWifPrivkey(privkey, is_testnet, False)
        return wif_privkey

def wif2privkey(wif: bytes):
        pass

def wifVerify(wif: bytes):
        pass

if __name__ == '__main__':
        privkey = binascii.unhexlify('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')
        wif_privkey = privkey2wif(privkey, False)
        print('wif private key = %s' % wif_privkey)

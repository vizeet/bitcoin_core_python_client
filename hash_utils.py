import hashlib

def hash160(secret: bytes):
        secrethash = hashlib.sha256(secret).digest()
        h = hashlib.new('ripemd160')
        h.update(secrethash)
        secret_hash160 = h.digest()
        return secret_hash160

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

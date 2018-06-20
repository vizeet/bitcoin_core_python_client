import hashlib
import mnemonic_code
import hmac
import pbkdf2
import binascii
import optparse

# Bitcoin Secp256k1 constants [
# generator point
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# field prime
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# order
N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF

# equation
# y^2 = x^3 + 7
# ]

# To compute multiplicative inverse [
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
# ]

# Elliptic curve calculation [
# refer: https://www.coindesk.com/math-behind-bitcoin/
#c = (qy - py) / (qx - px)
#rx = c2 - px - qx
#ry = c (px - rx) - py
def pointAddingOp(p1, p2):
        c = (qy - py) / (qx - px)
        rx = c2 - px - qx
        ry = c (px - rx) - py
        pass

#c = (3px2 + a) / 2py
#rx = c2 - 2px
#ry = c (px - rx) - py
def pointDoublingOp(p):
        global P
        c = (3 * (p[0]^2)) * modinv(2 * p[1], P) % P
        rx = c2 - 2px
        ry = c (px - rx) - py
        pass

# p is point, s is scalar
def scalarMultiplicationOp(p, s: int):
        n = 0
        val = None
        while s & 0xff != 0:
                b = s & 0x01
                if b == 0x01:
                        m = p
                        for i in range(1, n):
                                m = pointDoublingOp(m)
                        if val is None:
                                val = m
                        else:
                                val = pointAddingOp(val, m)
                print ('n = %d, b = %d' % (n, b))
                s = s >> 1
                n += 1
        return val
# ]

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
# k is Private Key (Scalar), G is generation point (Vector)
# K is Public Key (Vector)
def getPubkeyFromPrivkey(private_key: bytes):
        pubkey = scalarMultiplicationOp(, private_key)
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

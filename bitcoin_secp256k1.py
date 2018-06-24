from elliptic_curve_math import EllipticCurveMath
import binascii

class BitcoinSec256k1:
        # Bitcoin Secp256k1 constants [
        # generator point
        G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

        # field prime
        P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

        # order
        N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF
        print('order = %x' % N)

        a = 0
        b = 7

        # equation
        # y^2 = x^3 + 7
        # ]
        def __init__(self):
                self.elliptic = EllipticCurveMath(self.G, self.P, self.N, 0, 7)

        def privkey2pubkey(self, k: int, compress: bool):
                K = self.elliptic.scalarMultiplicationOp(self.G, k)
                if compress == False:
                        print('04%x%x' % (K[0], K[1]))
                        pubkey = b'\x04' + binascii.unhexlify(str('%064x' % K[0])) + binascii.unhexlify(str('%064x' % K[1]))
                        print(pubkey)
                        return pubkey
                else:
                        if K[1] % 2 == 0: # even
                                print('02%x' % K[0])
                                pubkey = b'\x02' + binascii.unhexlify(str('%032x' % K[0]))
                                return pubkey
                        else:
                                print('03%x' % K[0])
                                pubkey = b'\x03' + binascii.unhexlify(str('%032x' % K[0]))
                                return pubkey

if __name__ == '__main__':

        bitcoin_sec256k1 = BitcoinSec256k1()
        pubkey = bitcoin_sec256k1.privkey2pubkey(0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725, True)
        print('pubkey = %s' % bytes.decode(binascii.hexlify(pubkey)))

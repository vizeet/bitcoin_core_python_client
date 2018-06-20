class EllipticCurveMath:
        # G: Generation Point
        # P: Field Prime
        # N: Order
        def __init__(self, _G, _P: int, _N: int, _a: int, _b: int):
                self.G = _G
                self.P = _P
                self.N = _N
                self.a = _a
                self.b = _b

        # To compute multiplicative inverse [
        def egcd(self, a, b):
            if a == 0:
                return (b, 0, 1)
            else:
                g, y, x = self.egcd(b % a, a)
                return (g, x - (b // a) * y, y)

        def modinv(self, a, p):
            if a < 0 or a >= p: a = a % p
            c, d, uc, vc, ud, vd = a, p, 1, 0, 0, 1
            while c:
                q, c, d = divmod(d, c) + (c,)
                uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
            if ud > 0: return ud
            return ud + p

#        def modinv(self, a, m):
#            g, x, y = self.egcd(a, m)
#            if g != 1:
#                raise Exception('modular inverse does not exist')
#            else:
#                return x % m
        # ]

        # Elliptic curve calculation [
        # refer: https://www.coindesk.com/math-behind-bitcoin/
        #c = (qy - py) / (qx - px)
        #rx = c2 - px - qx
        #ry = c (px - rx) - py
        def pointAddingOp(self, p, q):
                c = ((q[1] - p[1]) * self.modinv(q[0] - p[0], self.P)) % self.P
                rx = (c * c - p[0] - q[0]) % self.P
                ry = (c * (p[0] - rx) - p[1]) % self.P
                r = (rx, ry)
                return r

        #c = (3px2 + a) / 2py
        #rx = c2 - 2px
        #ry = c (px - rx) - py
        def pointDoublingOp(self, p):
                c = ((3 * (p[0] * p[0]) + self.a) * self.modinv(2 * p[1], self.P)) % self.P
                rx = (c * c - 2 * p[0]) % self.P
                ry = (c * (p[0] - rx) - p[1]) % self.P
                r = (rx, ry)
                return r

        # p is point, s is scalar
        def scalarMultiplicationOp(self, p, s: int):
                if self.N: 
                        s %= self.N
                n = 0
                val = None
                while s & 0xff != 0:
                        b = s & 0x01
                        if b == 0x01:
                                m = p
                                for i in range(1, n + 1):
                                        m = self.pointDoublingOp(m)
                                        print('doubling')
                                if val is None:
                                        val = m
                                else:
                                        val = self.pointAddingOp(val, m)
                                        print('adding')
                        print ('n = %d, b = %d' % (n, b))
                        s = s >> 1
                        n += 1
                return val
        # ]

#if __name__ == '__main__':
#        elliptic = EllipticCurveMath((2, 22))
#        elliptic.setVars(67, 79, 0, 7)
#        m = elliptic.scalarMultiplicationOp((2, 22), 2)
#        print(m)

if __name__ == '__main__':
        elliptic = EllipticCurveMath((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))
        elliptic.setVars(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 0, 7)
        m = elliptic.scalarMultiplicationOp((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725)
        print('04 %x %x' % (m[0], m[1]))

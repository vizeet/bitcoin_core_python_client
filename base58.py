import hashlib
import binascii

g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

def hash256(bstr):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def base58_encode(num: int):
        global g_alphabet, g_base_count
        """ Returns num in a base58-encoded string """
        encode = ''

        if (num < 0):
                return ''

        while (num >= g_base_count):
                mod = num % g_base_count
                encode = g_alphabet[mod] + encode
                num = num // g_base_count

        if (num >= 0):
                encode = g_alphabet[num] + encode

        return encode

def base58_decode(s: str):
        global g_alphabet, g_base_count
        """ Decodes the base58-encoded string s into an integer """
        decoded = 0
        multi = 1
        s = s[::-1]
        for char in s:
                decoded += multi * g_alphabet.index(char)
                multi = multi * g_base_count
                
        return decoded

def base58checkEncode(prefix: bytes, h: bytes):
        with_prefix = prefix + h
        print('with prefx = %s' % bytes.decode(binascii.hexlify(with_prefix)))
        with_checksum = with_prefix + hash256(with_prefix)[0:4]
        print('with prefx and checksum = %s' % bytes.decode(binascii.hexlify(with_checksum)))
        print('with prefix and checksum int = %x' % int(binascii.hexlify(with_checksum[1:]), 16))
        encode = base58_encode(int(binascii.hexlify(with_checksum), 16))
        if prefix == b'\x00':
                encoded_prefix = base58_encode(0)
                encode = encoded_prefix + encode
        print('encoded base58 = %s' % encode)
        return encode

def base58checkVerify(prefix: bytes, val: str):
        decoded_val = base58_decode(val)
        postfix = binascii.unhexlify('%x' % decoded_val)[-4:]
        print('hash from value = %s' % bytes.decode(binascii.hexlify(postfix)))
        val_without_postfix = binascii.unhexlify('%x' % decoded_val)[0:-4]
        print('value = %s' % bytes.decode(binascii.hexlify(val_without_postfix)))
        val_with_prefix = prefix + val_without_postfix
        print('value = %s' % bytes.decode(binascii.hexlify(val_with_prefix)))
        h = hash256(val_with_prefix)[0:4]
        print('hash of value = %s' % bytes.decode(binascii.hexlify(h)))
        if h == postfix:
                return True
        return False

if __name__ == '__main__':
#        b58_str = 'xprv9s21ZrQH143K2fpGDeSiVghhRbX6YY7yUZ78Ng644PevUa8YKHAYJAg9CCbzkXdZvKZ8Xevajm9rcfYU974Ed86rFzvE58Yq8DdYuAZso5d'
        b58_str = 'xprv9u5MtGh9yEv5L2KZDwmUSpd9SPgCYFg5ehkboGez6Wsw5Tw3Z6K5ocPH6gqNECkjUtZmiqbXcYJNYzf3HnzVLMxwzk8ewAQPmPjgjMRJUUj'
#        b58_str = 'xprv9u5MtGhJJuT3VWTbNxniyUb5JieoKHJFfcJhgQ2xt7AXsDBjyi3GqeWUZst5qYsR8B15HVYzgDJ97m43eVHgFXVNqdEJqtUPhqGDGYuwC98'
        print('base 58 decode = %x' % base58_decode(b58_str))

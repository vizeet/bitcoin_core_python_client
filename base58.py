
g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

def base58_encode(num):
        global g_alphabet, g_base_count
        """ Returns num in a base58-encoded string """
        encode = ''

        if (num < 0):
                return ''

        while (num >= g_base_count):
                mod = num % g_base_count
                encode = g_alphabet[mod] + encode
                num = num // g_base_count

        if (num):
                encode = g_alphabet[num] + encode

        return encode

def base58_decode(s):
        global g_alphabet, g_base_count
        """ Decodes the base58-encoded string s into an integer """
        decoded = 0
        multi = 1
        s = s[::-1]
        for char in s:
                decoded += multi * g_alphabet.index(char)
                multi = multi * g_base_count
                
        return decoded

if __name__ == '__main__':
#        b58_str = 'xprv9s21ZrQH143K2fpGDeSiVghhRbX6YY7yUZ78Ng644PevUa8YKHAYJAg9CCbzkXdZvKZ8Xevajm9rcfYU974Ed86rFzvE58Yq8DdYuAZso5d'
        b58_str = 'xprv9u5MtGh9yEv5L2KZDwmUSpd9SPgCYFg5ehkboGez6Wsw5Tw3Z6K5ocPH6gqNECkjUtZmiqbXcYJNYzf3HnzVLMxwzk8ewAQPmPjgjMRJUUj'
#        b58_str = 'xprv9u5MtGhJJuT3VWTbNxniyUb5JieoKHJFfcJhgQ2xt7AXsDBjyi3GqeWUZst5qYsR8B15HVYzgDJ97m43eVHgFXVNqdEJqtUPhqGDGYuwC98'
        print('base 58 decode = %x' % base58_decode(b58_str))

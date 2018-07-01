import hashlib
import random_number_generator
import binascii
from functools import reduce

def getMnemonicWordSelectorBits():
        rnd_bits = random_number_generator.get256BitRandomNumber()
#        rnd_str = '2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c'
#        print('Random String = %s' % rnd_str.upper())
        print('Random String = %s' % bytes.decode(binascii.hexlify(rnd_bits)).upper())
#        rnd_bits = binascii.unhexlify('2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c')
        mnemonic_selector_bits = rnd_bits + hashlib.sha256(rnd_bits).digest()[0:1]
        return mnemonic_selector_bits

def getMnemonicWordList():
        word_list = []
        with open('mnemonic_word_list_english.txt', 'rt') as word_file:
                word_list = word_file.read().splitlines()
        return word_list

def convertSelectorBits2List(selector_bits: bytes, size: int):
        selector_int = int(binascii.hexlify(selector_bits), 16)
        print('selector str = %s' % binascii.hexlify(selector_bits))
        print('selector int = %x' % selector_int)
        selector_list = []
        while size >= 11:
                selector_list.append(selector_int & 0x07FF)
                selector_int = selector_int >> 11
                size -= 11
        print('len of selector list = %d' % len(selector_list))
        return selector_list[::-1]

def convertSelectorList2Bits(selector_list: list):
        selector_list = selector_list
        selector_int = reduce(lambda x, y: (x << 11) | y, selector_list)
        print('III selector bits = %s' % hex(selector_int))
        selector_bits = binascii.unhexlify(hex(selector_int)[2:])
        return selector_bits

def getMnemonicWordCodeString():
        word_list = getMnemonicWordList()

        selector_bits = getMnemonicWordSelectorBits()
        selector_list = convertSelectorBits2List(selector_bits, 264)
        mnemonic_word_list = getMnemonicWordList()
        word_key_list = [mnemonic_word_list[selector] for selector in selector_list]

        return ' '.join(word_key_list)

def verifyChecksumInSelectorBits(selector_bits: bytes):
        rnd_bits = selector_bits[0:32]
        checksum = selector_bits[-1]
        return (hashlib.sha256(rnd_bits).digest()[0] == checksum)

def verifyMnemonicWordCodeString(mnemonic_code: str):
        word_key_list = mnemonic_code.split(' ')
        mnemonic_word_list = getMnemonicWordList()
        selector_list = [mnemonic_word_list.index(word) for word in word_key_list]
        selector_bits = convertSelectorList2Bits(selector_list)
        return verifyChecksumInSelectorBits(selector_bits)

if __name__ == '__main__':
        word_key_list = getMnemonicWordCodeString()

        print('mnemonic key list = %s' % word_key_list)

        print('is valid = %r' % verifyMnemonicWordCodeString(word_key_list))

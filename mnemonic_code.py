import hashlib
import random_number_generator
import binascii

def getMnemonicWordSelectorBits():
        rnd_bits = random_number_generator.get256BitRandomNumber()
        mnemonic_selector_bits = rnd_bits + hashlib.sha256(rnd_bits).digest()[0:8]
        return mnemonic_selector_bits

def getMnemonicWordList():
        word_list = []
        with open('mnemonic_word_list_english.txt', 'rt') as word_file:
                word_list = word_file.read().splitlines()
        return word_list

def convertSelectorBits2SelectorList(selector_bits: bytes, size: int):
        selector_int = int(binascii.hexlify(selector_bits), 16)
        print('selector str = %s' % binascii.hexlify(selector_bits))
        print('selector int = %x' % selector_int)
        selector_list = []
        while size >= 11:
                selector_list.append(selector_int & 0x07FF)
                selector_int = selector_int >> 11
                size -= 11
        print('len of selector list = %d' % len(selector_list))
        return selector_list

def getMnemonicWordCodeString():
        word_list = getMnemonicWordList()

        selector_bits = getMnemonicWordSelectorBits()
        selector_list = convertSelectorBits2SelectorList(selector_bits, 264)

        word_key_list = [getMnemonicWordList()[selector] for selector in selector_list]

        return ' '.join(word_key_list)

if __name__ == '__main__':
        word_key_list = getMnemonicWordKeyList()

        print('mnemonic key list = %s' % word_key_list)

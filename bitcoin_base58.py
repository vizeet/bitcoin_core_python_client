import base58
import binascii

base58_prefixes = {
        "Mainnet": {
                "PKH": 0x00,
                "SH": 0x05,
                "WIF_Uncompressed": 0x80,
                "WIF_Compressed": 0x80,
                "BIP32_Pubkey": 0x0488B21E,
                "BIP32_Privkey": 0x0488ADE4
        },
        "Testnet": {
                "PKH": 0x6F,
                "SH": 0xC4,
                "WIF_Uncompressed": 0xEF,
                "WIF_Compressed": 0xEF,
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        }
}

address_prefixes = {
        "Mainnet": {
                "PKH": "1",
                "SH": "3",
                "WIF_Uncompressed": 0x80,
                "WIF_Compressed": 0x80,
                "BIP32_Pubkey": 0x0488B21E,
                "BIP32_Privkey": 0x0488ADE4
        },
        "Testnet": {
                "PKH": "m",
                "SH": "2",
                "WIF_Uncompressed": 0xEF,
                "WIF_Compressed": 0xEF,
                "BIP32_Pubkey": 0x043587CF,
                "BIP32_Privkey": 0x04358394
        }
}

def forAddress(h: bytes, is_testnet: bool, is_script: bool):
        prefix = base58_prefixes[("Mainnet", "Testnet")[is_testnet == True]][("PKH", "SH")[is_script == True]]
        print('address prefix before encoding = %02x' % prefix)
        address = base58.base58checkEncode(binascii.unhexlify('%02x' % prefix), h)
        return address

def addressVerify(address: str):
        prefix = address[0:1]
        is_valid = base58.base58checkVerify(prefix, address)
        return is_valid

def encodeWifPrivkey(h: int, is_testnet: bool, for_compressed_pubkey: bool):
        prefix = base58_prefixes[("Mainnet", "Testnet")[is_testnet == True]][("WIF_Uncompressed", "WIF_Compressed")[for_compressed_pubkey == True]]
        print('wif prefix before encoding = %02x' % prefix)
        h_b = binascii.unhexlify('%064x' % h)
        if for_compressed_pubkey == True:
                h_b = h_b + b'\01'
        wif_encoded = base58.base58checkEncode(binascii.unhexlify('%02x' % prefix), h_b)
        return wif_encoded

def decodeWifPrivkey(privkey_wif: str):
        pass

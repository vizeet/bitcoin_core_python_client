# bitcoin_core_python_client
Contains many useful Programs to parse bitcoin blockchain

## List of programs and their utility
1. blockfile_parser.py : Bitcoin blockchain is stored by default under "~/.bitcoin/blocks". This program parses those blocks to print in json format content of those files.
2. leveldb_parser.py: Bitcoin blockchain indexes are stored in leveldb databases. There are three databases
   i. Path ~/.bitcoin/blocks/index : Block index to determine last block and its predecessors in reverse order
   ii. Path ~/.bitcoin/chainstate : Metadata related unspent transaction outs
   iii. Path ~/.bitcoin/indexes/txindex : Provides offset and block number to reach each transaction
3. traverse_block_indexes.py : This program utilises bitcoin block index database stored under "~/.bitcoin/blocks/index/" to reverse traverse blockchain.
4. random_number_generator.py: This is random number generator which utilizes sound, webcam frames and system random utility to generate high entropy random number.
5. script_parser.py : Parses Bitcoin's reverse polish script
6. pubkey_address.py : Contains utility methods for private key, public key and address
7. mnemonic_code.py : Mnemonic code is a secret consisting of 12/15/18/24 words. The program generates mnemonic code from random number.
8. bitcoin_networkapis.py : Uses blockchain.info APIs to get some useful information
9. bitcoin_localapis.py : Uses bitcoin client RPC calls to implement useful methods

## List of Jupyter Notebook documents
1. BlockFileParser.ipynb : Contains information on structure of blockfile, blocks and transactions
2. BitcoinRPCUtils.ipynb : Contains many utility methods such as target threshold, current block size, actual block reward etc
3. BitcoinEllipticCurveCryptography.ipynb : Detailed information on Bitcoin elliptic curve cryptography

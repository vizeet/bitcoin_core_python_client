import plyvel
import os
import binascii

# Open the LevelDB
db = plyvel.DB(os.path.join(os.getenv('HOME'),".bitcoin/chainstate"), compression=None)

it = db.iterator(include_value=False)

key = next(it)
value = db.get(key)
obfuscation_key = value[1:]
print("first key = %s" % bytes.decode(binascii.hexlify(key)))
print("first value = %s" % bytes.decode(binascii.hexlify(value)))
print("obfuscation key = %s" % bytes.decode(binascii.hexlify(obfuscation_key)))

key = next(it)
value = db.get(key)

#for i in range(10):
#        key = next(it)
#        value = db.get(key)
#        print("[key, value] = [%s, %s]" % (bytes.decode(binascii.hexlify(key)), bytes.decode(binascii.hexlify(value))))
#        print("obfuscation repeated key = %s" % bytes.decode(binascii.hexlify(bytes(obfuscation_key[index % len(obfuscation_key)] for index in range(len(value))))))
#        new_val = bytes(value[index] ^ obfuscation_key[index % len(obfuscation_key)] for index in range(len(value)))
#        print("[key, new_value] = [%s, %s]" % (bytes.decode(binascii.hexlify(key)), bytes.decode(binascii.hexlify(new_val))))
#        txn_id = bytes.decode(binascii.hexlify(key[1:33][::-1]))
#        prefix = key[0]
#        print("prefix = %x, txn_id = %s" % (prefix, txn_id))

i = 0
for key, o_value in db:
#        print("[key, value] = [%s, %s]" % (key, o_value))
#        print("[key, value] = [%s, %s]" % (bytes.decode(binascii.hexlify(key)), bytes.decode(binascii.hexlify(o_value))))
        if i == 10:
                exit()
        i += 1
        prefix = key[0]
        if prefix is 0x43:
                txn_id = bytes.decode(binascii.hexlify(key[1:33][::-1]))
#                print("[key, value] = [%s, %s]" % (bytes.decode(binascii.hexlify(key[::-1])), bytes.decode(binascii.hexlify(o_value))))
                print("prefix = %x, txn_id = %s" % (prefix, txn_id))
#                version = o_value[0]
#                print('version = %d' % version)
 # do stuff

# Close the LevelDB
db.close()

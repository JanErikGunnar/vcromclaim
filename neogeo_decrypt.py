#!/usr/bin/env python3

#from neogeo_keys import keys
import os, hashlib
from u8archive import U8Archive

try:
    from Crypto.Cipher import AES
except:
    pass



def tryGetU8Archive(path):
    try:
        u8arc = U8Archive(path)
        if not u8arc:
            return None
        else:
            return u8arc
    except AssertionError:
        return None


def get_banner(folder):
    # find the banner.bin file, which may be in any of the U8Archives in the folder
    for app in os.listdir(folder):
        app_path = os.path.join(folder, app) 
        u8arc = tryGetU8Archive(app_path)
        if u8arc:
            for file in u8arc.files:
                if file.name == 'banner.bin':
                    file_as_bytesIO = u8arc.getfile(file.path)
                    file_as_bytearray = bytearray(file_as_bytesIO.read())
                    file_as_bytesIO.close()
                    return file_as_bytearray

    raise ValueError

def xor_bytearray(ba1, ba2):
    assert len(ba1) == len(ba2)
    out = bytearray(len(ba1))
    for i in range(0, len(out)):
        out[i] = ba1[i] ^ ba2[i]
    return out



def scramble_16_bytes(input_data):
    # 8019a5c4--8019a630
    data_1 = bytearray(16)
    for i in range(0,16):
        data_1[i] = input_data[i] ^ 0xFF

    # 8019a644--8019a6b0
    data_2 = bytearray(16)
    work_byte = 0xFF
    for i in range(0,16):
        work_byte ^= data_1[i]
        data_2[i] = work_byte

    # 8019a6c0--8019a764
    data_3 = bytearray(16)
    for i in range(0,16):
        work_byte = data_2[i]
        for j in [0,3,3]:
            shift_amount = (work_byte >> j) & 7
            work_byte = ((work_byte << (8-shift_amount)) | (work_byte >> shift_amount)) & 0xFF
        data_3[i] = work_byte

    # 8019a77c--8019a834
    data_4 = bytearray(16)
    carry_over_to_next_byte = 0
    for i in range(0,16):
        shift_amount = (data_3[i] >> (carry_over_to_next_byte & 7)) & 7
        shifted = carry_over_to_next_byte | ((data_3[i] << shift_amount) & 0xFF)
        data_4[i] = shifted
        carry_over_to_next_byte = shifted >> (8-shift_amount)

    # 8019a844--8019a8d0
    data_5 = bytearray(16)
    last_input_byte = 0
    for i in range(0,16):
        data_5[i] = (last_input_byte + data_4[i]) & 0xFF
        last_input_byte = data_4[i]

    return data_5
    

def get_aes_key(folder, cr00_key):
    return scramble_16_bytes(
        hashlib.md5(
            xor_bytearray(
                hashlib.md5(
                    get_banner(folder)
                ).digest(),
                cr00_key
            ),
        ).digest()
    )


# titleIdString must be the 8 byte string identifying each Wii title, e.g. '421a2b3c'
# fileString input must be a string containing the content of the encrypted romfile, starting with CR00.
# will return a tuple - either (true, decryptedData) or (false, encryptedData)
# note that the decryptedData will still be compressed (zipped), similar to some other neo geo games without encryption.
def decrypt_neogeo(sourceFolderPath, titleIdString, fileString):
    # encrypted files starts with a magic word
    assert fileString[0:4] == b'CR00'

    # the next 16 bytes are used as input for key generation.
    key = get_aes_key(sourceFolderPath, bytearray(fileString[4:0x14]))

    # the rest of the files is AES-CBC-128 encrypted. as such it consists of 16 byte (128bit) blocks.
    assert (len(fileString) - 0x14) % 0x10 == 0

    encryptedString = fileString[0x14:]
    assert len(fileString) == 0x14+len(encryptedString)

    #if (titleIdString in keys):
    #    if key == unhexlify(keys[titleIdString]):
    #        print("FOUND MATCHING KEY!!!!!!!!!! SUCCESS",key, keys[titleIdString])
    #    else:
    #        print("NOT MATCHING! :(",key, keys[titleIdString])
    #else:
    #        print("key not found in good list, assuming it's OK")
    
    # The IV is just zeroes.
    # If the IV is wrong, only the first block (16 bytes) will be decrypted incorrectly,
    # but that's bad enough for the decompression to fail
    zeroIv = b'\x00'*16

    assert len(key) == 16

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=zeroIv)
        decryptedString = cipher.decrypt(encryptedString)
    except:
        print("Got the key, but AES decryption failed. Make sure PyCryptodome or PyCrypto is installed.")
        return (False, encryptedString)

    assert len(decryptedString) == len(encryptedString)

    print("Found the AES key and decrypted the ROMs")

    return (True, decryptedString)

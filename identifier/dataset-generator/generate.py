import base64
import codecs
import csv
import hashlib
import os
import re


script_path = os.path.dirname(__file__)
dataset_path = script_path + "/../dataset/"

header = [
    'type',
    'encoded_text',
    'num_of_chars',
    'contains_bit_only',
    'contains_decimal_only',
    'contains_hex_only',
    'contains_alpha_only',
    'contains_upper_case_only',
    'contains_lower_case_only',
    'contains_mixed_upper_lower_case',
    'contains_equal',
    'contains_special_chars'
]
num_per_hash_for_train = 400
num_per_hash_for_test = 100


alphabet = "abcdefghijklmnopqrstuvwxyz"
letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)), alphabet))

def create_row(hash, hash_type):
    return [
        hash_type,
        hash,
        len(hash),
        contains_bit_only(hash),
        contains_decimal_only(hash),
        contains_hex_only(hash),
        contains_alpha_only(hash),
        contains_upper_case_only(hash),
        contains_lower_case_only(hash),
        contains_mixed_upper_lower_case(hash),
        contains_equal(hash),
        contains_special_chars(hash)
    ]


def contains_bit_only(chars):
    return int(re.search("[^01]", chars) is None)


def contains_decimal_only(chars):
    return int(re.search("[^0-9]", chars) is None)


def contains_hex_only(chars):
    for ch in chars:
        if re.match("[0-9a-fA-F]", ch) is None:
            return int(False)
    return int(True)


def contains_alpha_only(chars):
    return int(chars.isalpha())


def contains_upper_case_only(chars):
    return int(chars.isupper())


def contains_lower_case_only(chars):
    return int(chars.islower())


def contains_mixed_upper_lower_case(chars):
    upper = re.findall("[a-z]", chars)
    lower = re.findall("[A-Z]", chars)
    return int(len(upper) > 0 and len(lower) > 0)


def contains_equal(chars):
    return int(len(re.findall("\=", chars)) > 0)


def contains_special_chars(chars):
    return int(len(re.findall("\W", chars)) > 0)


def data_atbash(w):
    hash = ''.join([chr(ord('z') + ord('a') - ord(x)) for x in w])
    return create_row(hash, 'Atbash')


def data_binary(w):
    hash = ''.join(format(ord(x), 'b') for x in w)
    return create_row(hash, 'Binary')


def data_base32(w):
    hash = base64.b32encode(w.encode('utf-8')).decode()
    return create_row(hash, 'Base32')


def data_base64(w):
    hash = base64.b64encode(w.encode('utf-8')).decode()
    return create_row(hash, 'Base64')


def data_caesar(w):
    hash = ""
    s = 4 # shift pattern
    for i in range(len(w)):
        char = w[i]
        if (char.isupper()):
            hash += chr((ord(char) + s-65) % 26 + 65)
        else:
            hash += chr((ord(char) + s-97) % 26 + 97)
    return create_row(hash, 'Caesar')


def data_decimal(w):
    hash = ''.join(format(ord(x), 'd') for x in w)
    return create_row(hash, 'Decimal')


def data_hex(w):
    hash = ''.join(format(ord(x), 'x') for x in w)
    return create_row(hash, 'Hex')


def data_md4(w):
    hash = hashlib.new('md4', w.encode('utf-8')).hexdigest()
    return create_row(hash, 'MD4')


def data_md5(w):
    hash = hashlib.md5(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'MD5')


def data_ntlm(w):
    hash = hashlib.new('md4', w.encode('utf-16le')).hexdigest()
    return create_row(hash, 'NTLM')


def data_pbkdf2_hmac_sha256(w):
    hash = hashlib.pbkdf2_hmac('SHA256', w.encode('utf-8'), b'salt'*2, 1000).hex()
    return create_row(hash, 'PBKDF2-HMAC-SHA256')


def data_rot13(w):
    hash = codecs.encode(w, 'rot_13')
    return create_row(hash, 'ROT13')


def data_rot47(w):
    chars = []
    for ch in range(len(w)):
        ord_val = ord(w[ch])
        if ord_val >= 33 and ord_val <= 126:
            chars.append(chr(33 + ((ord_val + 14) % 94)))
        else:
            chars.append(w[ch])
    hash = ''.join(chars)
    return create_row(hash, 'ROT47')


def data_sha1(w):
    hash = hashlib.sha1(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA1')


def data_sha224(w):
    hash = hashlib.sha224(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA224')


def data_sha256(w):
    hash = hashlib.sha256(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA256')


def data_sha384(w):
    hash = hashlib.sha384(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA384')


def data_sha512(w):
    hash = hashlib.sha512(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA512')


def data_sha3_224(w):
    hash = hashlib.sha3_224(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-224')


def data_sha3_256(w):
    hash = hashlib.sha3_256(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-256')


def data_sha3_384(w):
    hash = hashlib.sha3_384(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-384')


def data_sha3_512(w):
    hash = hashlib.sha3_512(w.encode('utf-8')).hexdigest()
    return create_row(hash, 'SHA3-512')


def data_vigenere(w):
    hash = ""
    key = "key"

    try:
        split_w = [
            w[i : i + len(key)] for i in range(0, len(w), len(key))
        ]

        for s in split_w:
            i = 0
            for letter in s:
                number = (letter_to_index[letter] + letter_to_index[key[i]]) % len(alphabet)
                hash += index_to_letter[number]
                i += 1
        return create_row(hash, 'Vigenere')
    except:
        print(f"{w}: Cannot generate Vigenere Cipher.")


def create_datas(w):
    datas = []
    datas.append(data_atbash(w))
    datas.append(data_base32(w))
    datas.append(data_base64(w))
    datas.append(data_binary(w))
    datas.append(data_caesar(w))
    datas.append(data_decimal(w))
    datas.append(data_hex(w))
    datas.append(data_md4(w))
    datas.append(data_md5(w))
    datas.append(data_ntlm(w))
    datas.append(data_pbkdf2_hmac_sha256(w))
    # datas.append(data_rot13(w))
    # datas.append(data_rot47(w))
    datas.append(data_sha1(w))
    datas.append(data_sha224(w))
    datas.append(data_sha256(w))
    datas.append(data_sha384(w))
    datas.append(data_sha512(w))
    datas.append(data_sha3_224(w))
    datas.append(data_sha3_256(w))
    datas.append(data_sha3_384(w))
    datas.append(data_sha3_512(w))

    d_vigenere = data_vigenere(w)
    if d_vigenere is not None:
        datas.append(data_vigenere(w))

    return datas


def write_csv(filepath, header, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(data)


def main():
    datas_train = []
    datas_test = []
    
    with open(script_path + '/words.txt', 'r', encoding='utf-8') as f:
        words = [w.rstrip() for w in f.readlines()]
        for idx, word in enumerate(words):
            if 0 <= idx & idx < num_per_hash_for_train:
                datas_train += create_datas(word)
            elif num_per_hash_for_train <= idx & idx < num_per_hash_for_train + num_per_hash_for_test:
                datas_test += create_datas(word)

    write_csv(dataset_path + 'hashes_train.csv', header, datas_train)
    write_csv(dataset_path + 'hashes_test.csv', header, datas_test)

    print(f"Length of datas_train: {len(datas_train)}")
    print(f"Length of datas_test: {len(datas_test)}")

    print("Generated the hashes dataset successfully.")

main()
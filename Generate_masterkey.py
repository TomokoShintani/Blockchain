#マスター秘密鍵、マスター公開鍵の生成
import os
import binascii
import ecdsa
import hmac
import hashlib

seed = os.urandom(32)
root_key = b"Bitcoin seed"

#hmac_sha512はデータとキーの二つの入力を受け取り、512 bitsのハッシュ値を返す
def hmac_sha512(data, keymessage):
    hash = hmac.new(data, keymessage, hashlib.sha512).digest()
    return hash

#秘密鍵から公開鍵を作成
def create_pubkey(private_key):
    public_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).verifying_key.to_string()
    return public_key

master = hmac_sha512(seed, root_key)
master_secretkey = master[:32] #前半256 bitsを取得
master_chaincode = master[32:] #後半256 bitsを取得

#create_pubkey関数 → 入力：32 byte, 出力：64 byte
master_publickey = create_pubkey(master_secretkey)

print("master_secretkeyの長さは:{}".format(len(master_secretkey)))
print("master_publickeyの長さは:{}".format(len(master_publickey)))

#公開鍵の後半のy座標の部分を取得し、整数に変換
#正の数か負の数かで異なるprefixを付与し、圧縮公開鍵を生成
master_publickey_int = int.from_bytes(master_publickey[32:], byteorder="big")

if master_publickey_int % 2 == 0:
    master_publickey_x = b"\x02" + master_publickey[:32]

else:
    master_publickey_x = b"\x03" + master_publickey[:32]

#マスター秘密鍵の出力
print("master secret key: {}".format(binascii.hexlify(master_secretkey)))

#マスターチェーンコード
print("master chain code: {}".format(binascii.hexlify(master_chaincode)))

#マスター圧縮鍵
print("master public key: {}".format(binascii.hexlify(master_publickey_x)))

## binascii.hexlify()について
## バイト列を16進数文字列に変換する。
## 例えば、b'\x01\x02\x03'のようなバイト列が与えられた場合、
## binascii.hexlify(b'\x01\x02\x03')はb'010203'という16進数文字列を返す。



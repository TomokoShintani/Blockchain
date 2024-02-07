# 子鍵の生成
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

# ここから子鍵の生成
    
# 親公開鍵とインデックスを結合したものをdata, master_chaincodeをkeymessageとして
# hmac_sha512関数に渡す
index = 0
index_bytes = index.to_bytes(8, "big")
data = master_publickey_x + index_bytes
result_hmac512 = hmac_sha512(data, master_chaincode)

# 親秘密鍵とHMACSHA512の結果の前半部分を足し合わせる
sum_integer = int.from_bytes(master_secretkey, "big") + \
    int.from_bytes(result_hmac512[:32], "big")

#この際秘密鍵が32バイトよりも大きくならないように、
#巨大な素数であるpで割ってその余りを子秘密鍵として変数へ格納する。
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
child_secretkey = (sum_integer % p).to_bytes(32, "big")

print("child secret key: {}".format(binascii.hexlify(child_secretkey)))

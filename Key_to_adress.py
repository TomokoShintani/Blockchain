#秘密鍵から公開鍵を経てアドレスを生成する
#秘密鍵から公開鍵を生成する際に欠かせない楕円曲線暗号を直接自分で作るのは難易度が高く、脆弱性が高くなる可能性がある。
#よってここではecdsaというライブラリを使う。
import os
import ecdsa 
import hashlib
import base58

private_key = os.urandom(32)

#from_string関数の二つ目の引数で楕円曲線を指定
public_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).verifying_key.to_string()

#非圧縮公開鍵のprefixの04を公開鍵に付与
prefix_and_pubkey = b"\x04" + public_key

#公開鍵をSHA256でハッシュ化
intermediate = hashlib.sha256(prefix_and_pubkey).digest() #digestメソッドを通じてハッシュ値が返される。

#さらにRIPEMD-160でハッシュ化
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(intermediate)
hash160 = ripemd160.digest()

#公開鍵ハッシュのバージョンprefixである00と公開鍵ハッシュを合体させる。
prefix_and_hash160 = b"\x00" + hash160

#version prefix + 公開鍵ハッシュ　を2回SHA256でハッシュ化
double_hash = hashlib.sha256(hashlib.sha256(prefix_and_hash160).digest()).digest()
#先頭4 byteを取得
checksum = double_hash[:4]

#encodeする前のアドレス
pre_address = prefix_and_hash160 + checksum

#Base58Checkエンコード
address = base58.b58encode(pre_address)
print(address.decode())

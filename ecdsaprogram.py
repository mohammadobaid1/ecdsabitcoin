from ecdsa import SigningKey, SECP256k1,VerifyingKey

def getbothkeys():
    sk = SigningKey.generate(curve=SECP256k1)
    sk_string=sk.to_string()
    signingkey=sk_string.hex()
    print ('--------signing key----------',signingkey)
    vk = sk.get_verifying_key()
    verifykey=(vk.to_string()).hex()
    print ('------------verifying keys-----',verifykey)

def createsignature(signingkey,message):
    messagenecoded=message.encode('utf-8')
    signingkeybyte=bytes.fromhex(signingkey)
    signingkeyoriginal=SigningKey.from_string(signingkeybyte,curve=SECP256k1)
    digitalsignature=signingkeyoriginal.sign(messagenecoded)
    print ('-------digital signature',digitalsignature.hex())

def verifysignature(verifyingkey,digitalsignature,message):
    verify=bytes.fromhex(verifyingkey)
    getverifykey=VerifyingKey.from_string(verify, curve=SECP256k1)
    originalsignature=bytes.fromhex(digitalsignature)
    assert getverifykey.verify(originalsignature,message.encode('utf-8'))
    
    

getbothkeys()
    

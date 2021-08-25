from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

'''
MODO CBC
-> Key 16 - La llave de 16 bits
-> txtToCipher - El nombre del archivo de texto a encriptar
-> txtToReturn - El nombre del archivo de texto que se returna
'''
def AEScipher(key16, txtToCipher, txtToReturn):
    cipher = AES.new(key16, AES.MODE_CBC)
    iv = b64encode(cipher.iv).decode('utf-8')
    cipherTxt = open(txtToReturn,"w+")
    
    with open(txtToCipher) as a:
        for line in a:
            line = bytes(line, 'utf-8')
            ct_bytes = cipher.encrypt(pad(line, AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            cipherTxt.write(ct)

    a.close()
    cipherTxt.close()

    return str(iv), cipher.iv

def AESdecrypt(key16, cipherTxt, returnTxt, iv):
    cipher = AES.new(key16, AES.MODE_CBC, iv)
    decryptedTxt = open(returnTxt, 'w+')

    # Ahora se obtiene el texto
    with open(cipherTxt) as ctxt:
        line = ctxt.read()
        ct = b64decode(line)
        bt = unpad(cipher.decrypt(ct), AES.block_size)
        pt = bt.decode()
        decryptedTxt.write(pt)

    # Escribiendo en el txt y 
    ctxt.close()
    decryptedTxt.close()

def main():
    txt = 'prueba.txt'
    enctxt = 'prueba.enc'
    dectxt = 'prueba.dec'
    key = get_random_bytes(16)

    striv, iv =  AEScipher(key, txt, enctxt)
    AESdecrypt(key, enctxt, dectxt, iv)

if __name__ == '__main__':
    main()
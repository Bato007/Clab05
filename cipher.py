from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

'''
MODO CBC
-> Key 16 - La llave de 16 bits
-> txtToCipher - El nombre del archivo de texto a encriptar
-> txtToReturn - El nombre del archivo de texto que se retorna
'''

def bitChainTest(key16, chain, mode):
    result = ''
    # Encrypting Routine
    encAES = cipherMode(key16, mode)
    bitChain = bytes(chain, 'utf-8')
    enc = encAES.encrypt(pad(bitChain, AES.block_size))
    encMssg = b64encode(enc).decode('utf-8')
    # Decrypting Routine
    decAES = cipherMode(key16, mode, encAES.iv)
    hexChain = b64decode(encMssg)
    dec = unpad(decAES.decrypt(hexChain), AES.block_size)
    decMssg = dec.decode()

    result += '\n' + str(mode) + ' ENCRYPTING-DECRYPTING ROUTINE\n'
    result += '------------------------------------------\n'
    result += 'Original Message ---> '+ str(chain) + '\n'
    result += 'Encrypted Message --> '+ str(encMssg)  + '\n'
    result += 'Decrypted Message --> '+ str(decMssg) + '\n'

    return result 

def cipherMode(key16, mode, iv = None): # Allows the use of some modes

    if mode == 'CBC': # supports IV
        cipher = AES.new(key16, AES.MODE_CBC, iv)
    elif mode == 'CFB': # supports IV
        cipher = AES.new(key16, AES.MODE_CFB, iv) # Establece el modo de encripcion
    elif mode == 'OFB': # supports IV
        cipher = AES.new(key16, AES.MODE_OFB, iv)
    else: # Si se ingresa un modo inadecuado, lo ejecuta con CBC
        cipher = AES.new(key16, AES.MODE_CBC, iv)

    return cipher

def AEScipher(key16, txtToCipher, txtToReturn, mode):
    cipher = cipherMode(key16, mode)
    iv = b64encode(cipher.iv).decode('utf-8')
    cipherTxt = open(txtToReturn,"w+")
    with open(txtToCipher) as a:
        for line in a:
            line = bytes(line, 'utf-8')
            ct_bytes = cipher.encrypt(pad(line, AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            cipherTxt.write(ct + '\n')

    a.close()
    cipherTxt.close()

    return str(iv), cipher.iv

def AESdecrypt(key16, cipherTxt, returnTxt, iv, mode):
    cipher = cipherMode(key16, mode, iv)
    decryptedTxt = open(returnTxt, 'w+')

    # Ahora se obtiene el texto
    with open(cipherTxt) as ctxt:
        read = ctxt.read()
        lines = read.split('\n')
        for line in lines:
            if line:
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
    mode = 'CBC'

    striv, iv =  AEScipher(key, txt, enctxt, mode)
    AESdecrypt(key, enctxt, dectxt, iv, mode)

    print('\n--COMPARATIVE CHAIN MODE TEST--')
    print(
        bitChainTest(key, 'Hola Mundo', 'CBC'),
        bitChainTest(key, 'Hola Mundo', 'CFB'),
        bitChainTest(key, 'Hola Mundo', 'OFB')
        )
    print(
        bitChainTest(key, 'Adios Mundo', 'CBC'),
        bitChainTest(key, 'Adios Mundo', 'CFB'),
        bitChainTest(key, 'Adios Mundo', 'OFB')
        )
    print(
        bitChainTest(key, 'Ew Mundo', 'CBC'),
        bitChainTest(key, 'Ew Mundo', 'CFB'),
        bitChainTest(key, 'Ew Mundo', 'OFB')
        )
    
if __name__ == '__main__':
    main()
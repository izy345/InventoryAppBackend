from cryptography.fernet import Fernet

key = b'lsdsFB7as1P0Qtzgr1Tlx2W095n2htY1CRlle7apVNk='

class Cryptography():
  
    def Encrypt(text):  
        cipher_suite = Fernet(key)
        encrypted_secret_key = cipher_suite.encrypt(text.encode('utf-8'))
        return encrypted_secret_key
    
    def Decrypt(text):
        cipher_suite = Fernet(key)
        decrypted_secret_key = cipher_suite.decrypt(text)
        return decrypted_secret_key
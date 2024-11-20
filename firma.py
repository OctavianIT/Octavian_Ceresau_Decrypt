from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64

#Caricamento chiave privata
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None)
    

#Caricamento chiave pubblica
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key (key_file.read())
    

#-- Messaggio -- 
messagge = "Ciao, Epicode spacca!"

# Criptazione con la chiave pubblica
encrypted = public_key.encrypt (messagge.encode(), padding.PKCS1v15())

#Decriptazione con la chiave privata
decrypted = private_key.decrypt(encrypted, padding.PKCS1v15())

#print("Messaggio originale:", messagge)
print ("\nMessaggio criptato:\n", base64.b64encode(encrypted).decode("utf-8"))
print ("\nMessaggio decriptato:", decrypted.decode("utf-8"))



#Firma con la chiave privata
signed = private_key.sign( messagge.encode(), padding.PKCS1v15(), hashes.SHA256())

#Verifica della  firma con la chiave pubblica
try:
    encrypted_b64 = base64.b64encode(signed).decode("utf-8")
    public_key.verify(signed, messagge.encode(), padding.PKCS1v15(), hashes.SHA256())
    print ("\nBase 64 della firma:\n", encrypted_b64)
    print ("\nMessaggio originale da confrontare:", messagge)
    print ("\nLa firma è valida.")

except Exception as e:
    print ("\nLa firma non è valida", str(e))

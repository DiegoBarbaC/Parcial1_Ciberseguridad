import hashlib
import random

# Numero primo de RFC3526 de 1536 bits - MODFP Group

p = int ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
g = 2

print("\n", "**********************************")
print("\n", "        Variables publicas        ")
print("\n", "**********************************")
print("\n", "Numero privado compartido: " , p)
print("\n", "Numero publico compartido: " , g)

# Random, claves privadas entre Eve, Alice y Bob
sEve = random.getrandbits(256)
sAlice = random.getrandbits(256)
sBob = random.getrandbits(256)

print("\n", "Numero de alice: " , sAlice)
print("\n", "Numero de bob: " , sBob)
print("\n", "Número de Eve: ", sEve)

#Mensajes de Bob y Alice
A = pow(g, sAlice, p)
B = pow(g, sBob, p)

print("\n", f'Mensaje de Alice a Bob: {A}')
print("\n", f'Mensaje de Bob a Alice: {B}')

#Claves de Eve falsas
EB = pow(g, sEve, p)
EA = pow(g, sEve, p)

#Eve intercepta y alice y bob calculan llaves secretas con claves falsas
KAE = pow(EA, sAlice, p)  
KBE = pow(EB, sBob, p)

#Eve calcula claves secretas con Bob y Alice
KEA = pow(B, sEve, p)
KEB = pow(A, sEve, p)

if KAE == KEB:
    print("Eve obtuvo la clave secreta de Alice y Bob.")
else:
    print("Las llaves no son iguales.")

hash_key_AE = hashlib.sha256(str(KAE).encode()).hexdigest()
hash_key_BE = hashlib.sha256(str(KBE).encode()).hexdigest()
hash_key_EA = hashlib.sha256(str(KEA).encode()).hexdigest()
hash_key_EB = hashlib.sha256(str(KEB).encode()).hexdigest()
print("Hash de la llave compartida Alice a Eve:", hash_key_AE)
print("Hash de la llave compartida Bob a Eve:", hash_key_BE)
print("Hash de la llave compartida Eve a Alice:", hash_key_EA)
print("Hash de la llave compartida Bob a Alice:", hash_key_EB, "\n")
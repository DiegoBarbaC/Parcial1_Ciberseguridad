import Crypto.Util.number
import hashlib

#En firma se firma con mi llave privada para que cualquier persona pueda identificar mi firma con mi llave pública

e= 65537

#Calcular llave pública de Alice
pA= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
qA= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)



nA= pA*qA
print("RSA Llave pública de Alice: ", nA)

#Calcular llave pública de Bob
pB= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
qB= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)

nB= pB*qB
print("RSA Llave pública de Bob: ", nB)


#Calcular llave privada de Alice:
phiA= (pA-1)*(qA-1)

dA=Crypto.Util.number.inverse(e, phiA)
print("RSA Llave privada de Alice dA: ", dA)

#Calcular llave privada de Bob:
phiB= (pB-1)*(qB-1)

dB=Crypto.Util.number.inverse(e, phiB)
print("RSA Llave privada de Bob dB: ", dB)

mensaje= "Hola mundo"
print(mensaje)

#Generar el hash del mensaje
hM= int.from_bytes(hashlib.sha256(mensaje.encode('utf-8')).digest(),byteorder='big')
print("Hash de hM: ", hM)


#Firmamos hash usando llave privada de Alice y se lo enviamos a Bob
sA =pow(hM, dA, nA)
print("Firma: ", sA)

#Bob verifica la firma de Alice usando llave pública de Alice
hM1= pow(sA, e, nA)
print("Hash de hM1: ", hM1)

#Verificar
print("Firma válida: ", hM==hM1)


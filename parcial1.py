import Crypto.Util.number
import hashlib
import random
import string
import PyPDF2

e= 65537

#Generación de llaves de Alice y Bob

#Alice
#Calcular llave pública de Alice
pA= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
qA= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
nA= pA*qA
#print("RSA Llave pública de Alice: ", nA)
#Calcular llave privada de Alice:
phiA= (pA-1)*(qA-1)
dA=Crypto.Util.number.inverse(e, phiA)
#print("RSA Llave privada de Alice dA: ", dA)

#Bob
#Calcular llave pública de Bob
pB= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
qB= Crypto.Util.number.getPrime(1024, randfunc= Crypto.Random.get_random_bytes)
nB= pB*qB
#print("RSA Llave pública de Bob: ", nB)
#Calcular llave privada de Bob:
phiB= (pB-1)*(qB-1)
dB=Crypto.Util.number.inverse(e, phiB)
#print("RSA Llave privada de Bob dB: ", dB)

#AC
#Calcular llave pública de AC
pAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
#Calcular llave privada de AC
phiAC = (pAC-1)*(qAC-1)
dAC = Crypto.Util.number.inverse(e, phiAC)


#Funciones 

#Mensaje aleatorio
def generate_random_message(length=1050):
    characters = string.ascii_letters + string.digits + " "
    return ''.join(random.choices(characters, k=length))

#Separar mensaje en chunks de 128
def split_message(message, chunk_size=128):
    chunks = []  
    for i in range(0, len(message), chunk_size):  
        chunk = message[i:i + chunk_size]  
        chunks.append(chunk)  
    return chunks  

#Encriptar chunks
def encriptar_message(chunks, e, n):
    chunks_encripted=[]
    for chunk in chunks:
        chunk_number = int.from_bytes(chunk.encode('utf-8'), byteorder='big')
        chunk_encripted = pow(chunk_number, e, n)
        chunks_encripted.append(chunk_encripted)
    return chunks_encripted

#Funcion desencriptar
def desencriptar_message(chunks, d, n):
    chunks_desencripted=[]
    for chunk in chunks:
        chunk_number = pow(chunk, d, n)
        # Convertir de número a bytes y luego a texto
        chunk_desencripted = chunk_number.to_bytes((chunk_number.bit_length() + 7) // 8, 'big').decode('utf-8')
        chunks_desencripted.append(chunk_desencripted)
    return chunks_desencripted

#Flujo ejercicio 1

#Se genera el mensaje aleatorio de 1050 caracteres
message = generate_random_message()
print("Mensaje original: ", message)
#Se hace el hash del mensaje
hM= int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(),byteorder='big')
print("Hash del mensaje: ", hM)
#El mensaje se divide en chunks de 128 caracteres
chunks = split_message(message)
#Se encriptan los chunks con la llave pública de Bob y se le envían
chunks_encripted= encriptar_message(chunks, e, nB)
#Bob recibe los chunks encriptados y los desencripta con su llave privada
chunks_desencripted = desencriptar_message(chunks_encripted, dB, nB)

#Unir los chunks descifrados para obtener el mensaje original
mensaje_recuperado = ''.join(chunks_desencripted)

#Generar el hash del mensaje recuperado h(M')
hM_prima = int.from_bytes(hashlib.sha256(mensaje_recuperado.encode('utf-8')).digest(), byteorder='big')
print("Hash del mensaje recuperado: ", hM_prima)
#Verificar la integridad del mensaje comparando los hashes
if hM == hM_prima:
    print("Los hashes coinciden")
    print("Mensaje original recuperado:", mensaje_recuperado)
else:
    print("Los hashes no coinciden")


#Flujo ejercicio 2

def get_pdf_hash(pdf_path):
    with open(pdf_path, 'rb') as file:
        # Crear objeto PDF
        pdf_reader = PyPDF2.PdfReader(file)
        # Obtener el contenido del PDF
        content = ""
        for page in pdf_reader.pages:
            content += page.extract_text()
        # Calcular el hash del contenido
        return int.from_bytes(hashlib.sha256(content.encode('utf-8')).digest(), byteorder='big')

#Alice firma el documento
pdf_path = "NDA.pdf"
hM_pdf = get_pdf_hash(pdf_path)
print("Hash del PDF original: ", hM_pdf)

# Alice firma con su llave privada
firma_alice = pow(hM_pdf, dA, nA)
print("Firma de Alice:", firma_alice)

# AC verifica la firma de Alice
hM_verificado = pow(firma_alice, e, nA)
if hM_pdf == hM_verificado:
    print("Firma de Alice verificada por AC")
    # AC firma el documento
    firma_ac = pow(hM_pdf, dAC, nAC)
    print("Firma de AC:", firma_ac)
else:
    print("La firma de Alice no es válida")

#Bob verifica la firma de AC
hM_verificado_ac = pow(firma_ac, e, nAC)
if hM_pdf == hM_verificado_ac:
    print("Firma de AC verificada por Bob")
else:
    print("La firma de AC no es válida")
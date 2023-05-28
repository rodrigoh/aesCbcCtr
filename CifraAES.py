from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom


def cifraAESmodoCBC(chave, mensagem):
    #Gerando um vetor de inicialização de 16 bytes
    iv = urandom(16)
    # Cria um objeto Cipher com o algoritmo AES em modo CBC
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))

    # Criar um objeto de padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    # Adicionar padding à mensagem
    padded_message = padder.update(mensagem) + padder.finalize()

    # Criptografar a mensagem usando AES em modo CBC
    encryptor = cipher.encryptor()
    mensagemCifrada = encryptor.update(padded_message) + encryptor.finalize()

    return iv+mensagemCifrada


def decifraAESmodoCBC(chave, iv, mensagemCifrada):
    # Cria um objeto Cipher com o algoritmo AES em modo CBC
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))

    # Decifrar a mensagem usando AES em modo CBC
    decryptor = cipher.decryptor()
    mensagemPreenchimento = decryptor.update(mensagemCifrada) + decryptor.finalize()

    # Remover o padding da mensagem decifrada
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    mensagemDecifrada = unpadder.update(mensagemPreenchimento) + unpadder.finalize()

    # Imprimir a mensagem decifrada
    return mensagemDecifrada


def cifraAESmodoCTR(chave, mensagem):
    # Gerar um nonce número usado apenas uma vez aleatório de 64 bits ou 8 bytes
    nonce = urandom(16)

    # Criar um objeto Cipher com o algoritmo AES em modo CTR
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce), backend=default_backend())

    # Criptografar a mensagem
    encryptor = cipher.encryptor()
    mensagemCifrada = encryptor.update(mensagem) + encryptor.finalize()

    return nonce+mensagemCifrada


def decifraAESmodoCTR(chave, nonce, mensagemCifrada):

    # Criar um objeto Cipher com o algoritmo AES em modo CTR
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce), backend=default_backend())

    # Descriptografar a mensagem
    decryptor = cipher.decryptor()
    mensagemDecifrada = decryptor.update(mensagemCifrada) + decryptor.finalize()

    return mensagemDecifrada

#main
print("Cifra AES")
print("-----------------------------")
print("Escolha uma opção:")
print("1 - Cifrar")
print("2 - Decifrar")
opcao = input("Opção: ")
match opcao:
    case '1':
        print("Cifrando")
        print("-----------------------------")
        # Lendo o texto e convervendo para bytes
        textoClaro = bytes.fromhex(input('Digite o texto: '))
        print('Texto:', textoClaro)
        # Lê a chave e converte para bytes
        chave = bytes.fromhex(input('Digite a chave: '))
        modo = int(input('Escolha o modo de operação: 1 - CBC, 2 - CTR: '))
        if modo == 1:
            print('Trabalhando com CBC')
            mensagemCifrada = cifraAESmodoCBC(chave, textoClaro)
        else:
            print('Trabalhando com CTR')
            mensagemCifrada = cifraAESmodoCTR(chave, textoClaro)
        print('Mensagem cifrada: ', mensagemCifrada)
        mensagemCifradaHex = mensagemCifrada.hex()
        print('Mensagem cifrada em hexadecimal:', mensagemCifradaHex)
    case '2':
        print("Decifrando")
        print("-----------------------------")
        #Lendo o texto e convervendo para bytes
        mensagemCifrada = bytes.fromhex(input('Digite o texto cifrado: '))
        #Lê a chave e converte para bytes
        chave = bytes.fromhex(input('Digite a chave: '))
        # Pega até o 16º byte para o vetor de inicialização ou para o nonce
        vetorInicializacaoNonce = mensagemCifrada[:16]
        # Pega a partir do 16º byte para o texto cifrado
        textoCifrado = mensagemCifrada[16:]

        modo = int(input('Escolha o modo de operação: 1 - CBC, 2 - CTR: '))
        if modo == 1:
            print('Trabalhando com CBC')
            textoClaro = decifraAESmodoCBC(chave, vetorInicializacaoNonce, textoCifrado)
        else:
            print('Trabalhando com CTR')
            textoClaro = decifraAESmodoCTR(chave, vetorInicializacaoNonce, textoCifrado)
        print('Mensagem decifrada:', textoClaro)
        textoClaroHex = textoClaro.hex()
        print('Mensagem decifrada convertida para hexadecimal:', textoClaroHex)


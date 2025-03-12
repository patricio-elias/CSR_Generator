from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography import x509
from datetime import datetime, timedelta

def load_pem_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()
    

print("""
-----------------------------------------------------------------------------
   _____                    _                  _         _____  _____ _____  
  / ____|                  | |                | |       / ____|/ ____|  __ \ 
 | |  __  ___ _ __ __ _  __| | ___  _ __    __| | ___  | |    | (___ | |__) |
 | | |_ |/ _ \ '__/ _` |/ _` |/ _ \| '__|  / _` |/ _ \ | |     \___ \|  _  / 
 | |__| |  __/ | | (_| | (_| | (_) | |    | (_| |  __/ | |____ ____) | | \ \ 
  \_____|\___|_|  \__,_|\__,_|\___/|_|     \__,_|\___|  \_____|_____/|_|  \_\
                                                                             
-----------------------------------------------------------------------------  


Este código gera o CSR e Key para compra de certificado.

by: Patricio Elias
""")

def generate_csr_and_key(use_ecdsa, curve, rsa_pss):
    while True:
        common_name = input("Digite o Nome Comum (Common Name): ")
        organization = input("Organization: ")
        country = input("País com duas Letras ex BR: ")
        state = input("State ex. São Paulo: ")
        locality = input("Locality ex. Osasco: ")

        # Senha do certificado - se quiser não coloca
        password = input("Digite a senha para a chave privada (pressione Enter se não deseja senha): ")
        password_confirm = input("Confirme a senha: ")

        if password == password_confirm:
            break
        else:
            print("Senhas não coincidem. Reiniciando o processo.")

    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
    else:
        encryption_algorithm = serialization.NoEncryption()

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])

    if use_ecdsa:
        if curve == "1":
            private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        elif curve == "2":
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            print("Escolha de curva ECDSA inválida. Saindo.")
            return
        rsa_pss = False 
    else:
        if rsa_pss:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm if not use_ecdsa else serialization.NoEncryption()
    )

    private_key_filename = f'{common_name.replace(".", "_")}_private_key.pem' if use_ecdsa else f'{common_name.replace(".", "_")}_private_key.key'

    with open(private_key_filename, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    csr_filename = f'{common_name.replace(".", "_")}.csr'

    with open(csr_filename, 'wb') as csr_file:
        csr_file.write(csr_pem)

    print(f'CSR salvo em: {csr_filename}')
    print(f'Chave privada salva em: {private_key_filename}')

if __name__ == "__main__":
    cifra_escolha = input("Deseja usar qual cifra?\n1- RSA\n2- ECDSA P-521\n3- ECDSA P-384\nEscolha 1, 2 ou 3: ")
    use_ecdsa = cifra_escolha in ["2", "3"]

    if use_ecdsa:
        curve = input("Escolha a curva ECDSA (1 para P-521 ou 2 para P-384): ")
    else:
        curve = None

    rsa_pss = False  
    if not use_ecdsa:
        rsa_pss = input("Deseja usar RSA-PSS? (S/N): ").lower() == "s"

    generate_csr_and_key(use_ecdsa, curve, rsa_pss)

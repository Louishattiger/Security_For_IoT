from smartcard.System import readers
from smartcard.util import toHexString
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Recherche de lecteurs de cartes
# r = readers()
# if not r:
#    raise Exception("Aucun lecteur de carte n'a été trouvé.")

# reader = r[0]

# print("Lecteur de carte détecté:", reader)

# connection = reader.createConnection()
# connection.connect()

data_file_name = "input.txt"

try:
    user_input = input("Entrez le code PIN au format : ") 
    pin_apdu = [0x00, 0x20, 0x00, 0x00, 0x08]
    
    for nb in user_input:
        pin_apdu.append(int(nb))

    # data, sw1, sw2 = connection.transmit(pin_apdu)
    # if sw1 == 0x90 and sw2 == 0x00:
        # print("Code PIN correct :)")
    # else:
        # print("Code PIN incorrect :(")

    data_file_name = input("Entrez le nom du fichier de données à charger :") 

    data_apdu = [0x00, 0x20, 0x00, 0x00, 0x08]

    with open(data_file_name, 'r') as file:
        # Lire le contenu du fichier
        data = file.read()
        
        for nb in data:
            data_apdu.append(int(nb))

    # data, sw1, sw2 = connection.transmit(data_apdu)
    # if sw1 == 0x90 and sw2 == 0x00:
        # print("Transmission des données réussie")

        # result_file_name = input("Entrez le nom du fichier de sortie pour les données encryptées") 

        # print("Vérification de la signature reçue")

        # TO DO récupérer la signature 

        # if validate_signature(...)

        #   TO DO écrire dans le fichier de sortie les données encryptées récupérées

        #   print("Signature valide, les données encryptées se trouvent maintenant dans ....txt")

        # else 
        #   print("Signature non valide, données potentiellement corrompues")

    # else:
        # print("Code PIN incorrect :(")  

except FileNotFoundError:
    print("Le fichier '{data_file_name}' n'a pas été trouvé.")
except Exception as e:
    print("Erreur lors de la communication avec la carte: {e}")

# Ici la méthode validate_signature va utiliser la clé publique récupérée pour déchiffrer la signature et vérifier que c'est bien celle de la carte
# Pour info, donnée chiffrée avec une clé publique ---> peut seulement être déchiffrée par la clé privée correspondante
#            donnée chiffrée avec une clé privée --> peut être déchiffrée avec la clé publique

def validate_signature(data, signature, public_key):
    public_key = serialization.load_pem_public_key(public_key)
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True  
    except Exception:
        return False 

# connection.disconnect()

from smartcard.System import readers
from smartcard.util import toHexString

# Recherche de lecteurs de cartes
r = readers()

if not r:
    raise Exception("Aucun lecteur de carte n'a été trouvé.")

reader = r[0]

print("Lecteur de carte détecté:", reader)

connection = reader.createConnection()
connection.connect()

try:
    #Authentification sur la carte

    user_input = input("Entrez le code PIN : ")

    app_aid = [0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x05]

    connection.transmit(app_aid)

    pin_apdu = [0x00, 0x20, 0x00, 0x00, 0x04]

    for nb in user_input:
        pin_apdu.append(int(nb))

    dataPin, sw1Pin, sw2Pin = connection.transmit(pin_apdu)

    if sw1Pin == 0x90 and sw2Pin == 0x00:
        print("Code PIN correct :)")
    else:
        print("Code PIN incorrect :(");

    # Proposition de modification du code PIN

    user_input2 = input("Voulez-vous changer le code PIN (0 - oui, 1 - non) ?")

    if user_input2 == 0:
        user_input3 = input("Entrez le nouveau code PIN : ")

        new_pin_apdu = [0x00, 0x30, 0x00, 0x00, 0x04]

        for nb in user_input3:
            new_pin_apdu.append(int(nb))

        dataNewPin, sw1NewPin, sw2NewPin = connection.transmit(new_pin_apdu)

        if sw1NewPin == 0x90 and sw2NewPin == 0x00:
            print("Code PIN changé")
        else:
            print("Echec de la modification")

    # Récupération des données dans un fichier dans le même répertoire

    data_file_name = input("Entrez le nom du fichier de données à charger :")

    data_apdu = [0x00, 0x40, 0x00, 0x00, 0x04]

    with open(data_file_name, 'r') as file:
        data = file.read()

        for nb in data:
            data_apdu.append(int(nb))

    # Envoi et récupération des données signées par la carte

    dataSignature, sw1Signature, sw2Signature = connection.transmit(data_apdu)

    if sw1Signature == 0x90 and sw2Signature == 0x00:

        # Phase de vérification de la signature grâce à la clé publique

        print("Vérification de la signature ...")

        # Récupération de la clé publique

        public_key_apdu = [0x00, 0x50, 0x00, 0x00, 0x00]

        dataVerification, sw1Verification, sw2Verification = connection.transmit(public_key_apdu)

        if sw1Verification == 0x90 and sw2Verification == 0x00:

            public_key = serialization.load_pem_public_key(dataVerification)

            try:
                public_key.verify(dataSignature, data, padding.PKCS1(), hashes.SHA256())

                # Si la signature est vérifiée on écrit les données signées récupérées dans un fichier de sortie

                result_file_name = input("Entrez le nom du fichier de sortie pour les données encryptées")

                with open(result_file_name, 'w') as file2:
                    file2.write(dataSignature)

                print("Les données signées ont été copiées dans le fichier et la signature était valide !")

            except Exception:
                print("Signature non valide, données potentiellement corrompues")
    else:
        print("Echec de la récupération de la clé publique ou de l'envoi des données à signer")

except Exception as e:
    print(e);
    print("Erreur lors de la communication avec la carte")

connection.disconnect()

# Utilisation du l'application terminal

## Installation des dépendances 

Le fichier requirements.txt contient les dépendances nécéssaires au fonctionnement de l'application.

Pour les installer il est possible d'utiliser la commande suivante :
`pip install -r requirements.txt`

Il sera également nécessaire de télécharger Python3 pour lancer l'application

## Fonctionnement général

Cette application terminal ne fonctionne pas complètement.

Elle permet de s'authentifier sur la carte et de modifier le code PIN mais les autres envois d'APDU échouent. Elle a cependant été conçue pour réaliser la succession d'opérations suivantes :

- Demander le code PIN à l'utilisateur
- Demander s'il souhaite changer ce code (0 = oui, 1 = non)
- Si non, demander le nom du fichier dans lequel lire les données à signer
- Convertir ces données dans un format hexadécimal pour les envoyer sous la forme d'APDU
- Récupérer la clé publique de la carte
- Vérifier la signature reçue de la carte grâce à la clé publqiue
- Si la signature est vérifiée, écrire les données signées dans un fichier de sortie

Le fichier data.txt contient les données qui vont être envoyées à la carte pour être signées.

## Lancement de l'application

Pour démarrer notre client dans un terminal, il est possible d'utiliser la ligne de commande `python3 client.py`

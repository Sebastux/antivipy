#!/usr/bin/env python
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
import hashlib
import os
import mimetypes
import sys
import requests
from dotenv import load_dotenv, dotenv_values

# import json
# import rich

"""
classe permettant la gestion l'upload de fichiers et la récupération du résultat du scan antivirus
"""


# self.url = "https://www.virustotal.com/api/v3/files"

class Antivipy:
    def __init__(self, nom_fichier: str):
        self.url = "https://httpbin.org/"
        self.url_scan = "https://www.virustotal.com/"
        self.hash_fichier = ""
        self.files = nom_fichier
        self.nom_fichier = nom_fichier

        # Récupération des variables d'environement.
        load_dotenv(".env", verbose=False, encoding="utf-8", override=False)
        if os.getenv("API_KEY") is not None:
            self.cle_api = os.getenv("API_KEY")
            self.headers = {
                "accept": "application/json",
                "x-apikey": self.cle_api
            }
        else:
            self.cle_api = ""

        if os.getenv("PASSWD") is not None:
            self.passwd = os.getenv("PASSWD")
        else:
            self.passwd = ""

        self.files = {"file": (self.nom_fichier, open(self.nom_fichier, "rb"), mimetypes.guess_type(self.nom_fichier))}

    def hash_fichier(self):
        # Hashage du fichier
        if os.path.isfile(self.args.file) is True:
            with open(self.args.file, 'rb') as f:
                data = f.read()
                self.hash_fichier = hashlib.sha256(data).hexdigest()
        else:
            print(f"Impossible d'ouvrir le fichier {args.file} car celui-ci n'est pas à l'emplacement indiqué.")
            sys.exit(1)

    def upload_fic(self) -> int
        if self.passwd is not None:
            payload = {"password": self.passwd}
            response = requests.post(url, data=payload, files=files, headers=headers)
        else:
            response = requests.post(url, files=files, headers=headers)
            passwd = "L'archive ne posséde pas de mot de passe."

        return response.status_code


def main():
    parser = ArgumentParser()

    # Ajout des arguments
    parser.add_argument("-f", "--file", help="Chemin du fichier à analyser.", required=True, type=str,
                        dest="file")
    parser.add_argument("-o", "--output", help="Chemin du fichier qui contiendra le résultat du scan antivirus.",
                        required=False, type=str, dest="output")
    parser.add_argument("-O", "--output_url", help="Chemin du fichier qui contiendra l'url du scan antivirus.",
                        required=False, type=str, dest="output_url")
    parser.add_argument("-y", "--yes", help="Répondre oui à toutes les questions posées par le script.",
                        required=False, action='store_true', dest="yes")
    args = parser.parse_args()

    sys.exit(0)
    # if response.status_code != 200:
    #     print("L'analyse du fichier a échoué.\n")
    #     sys.exit(1)
    # elif response.status_code == 200:
    #     print("L'analyse du fichier est en cours.")


if __name__ == "__main__":
    main()

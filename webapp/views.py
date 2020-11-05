from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views import View
from django.template.response import TemplateResponse
from django.views.decorators.csrf import ensure_csrf_cookie,csrf_protect, csrf_exempt
from django.middleware.csrf import get_token
import html
# Create your views here.
#Crypto libraries
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
#
import json
#
import string



key = b"YELLOW SUBMARINE"


def cifrar(plaintext):
    ciphertext = ""
    if len(plaintext) > 0:
        cipher = AES.new(key, AES.MODE_ECB)
        msg = cipher.encrypt(pad(bytes(plaintext.encode('utf-8')), AES.block_size))
        ciphertext = msg.hex()
    return ciphertext

#@csrf_exempt
class CifradorView(View):
    def get(self,request):
        plaintext = request.session.get('plaintext', False) #Get a session value, setting False a default if it is not present
        ciphertext = request.session.get('ciphertext', False)
        if (plaintext): del (request.session['plaintext'])
        if (ciphertext): del (request.session['ciphertext'])
        return render(request, 'webapp/cifrador.html',{'textocifrado' : ciphertext, 'textoplano':plaintext})

    def post(self,request):
        plaintext = request.POST['plaintext']
        ciphertext = cifrar(plaintext)
        request.session['plaintext'] = plaintext
        request.session['ciphertext'] = ciphertext
        return redirect(request.path)


def descifrar(ciphertext):
    plaintext = ""
    if len(ciphertext) > 0:
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size).decode('utf-8')
    return plaintext

#@csrf_exempt
class DescifradorView(View):
    def get(self, request):
        plaintext = request.session.get('plaintext', False)  # Get a session value, setting False a default if it is not present
        ciphertext = request.session.get('ciphertext', False)
        right_len = request.session.get('right_len', True)
        ishex = request.session.get('ishex', True)
        if (plaintext): del (request.session['plaintext'])
        if (ciphertext): del (request.session['ciphertext'])
        if (right_len == False): del (request.session['right_len'])
        if (ishex == False): del (request.session['ishex'])
        dic = {'textocifrado': ciphertext, 'textoplano': plaintext, 'longitud': right_len, 'hexa': ishex}
        return render(request, 'webapp/descifrador.html', dic)

    def post(self, request):
        ciphertext = request.POST['ciphertext']
        ishex = all(c in string.hexdigits for c in ciphertext)  # check is the input string is hex
        right_len = len(ciphertext) % 32 == 0
        if ishex and right_len:
            plaintext = descifrar(ciphertext)
            request.session['plaintext'] = plaintext
        request.session['ciphertext'] = ciphertext
        request.session['right_len'] = right_len
        request.session['ishex'] = ishex
        return redirect(request.path)


keyPair = RSA.generate(bits=1024) # it can also be imported from a file
pubKey = keyPair.publickey()


def firmar(document):
    signature = ""
    if len(document) > 0:
        hash = SHA256.new(bytes(document, 'utf-8'))
        signer = PKCS115_SigScheme(keyPair)
        signature = signer.sign(hash).hex()
    return signature


class FirmadorView(View):
    def get(self,request):
        document = request.session.get('document', False) #Get a session value, setting False a default if it is not present
        signature = request.session.get('signature', False)
        if (document): del (request.session['document'])
        if (signature): del (request.session['signature'])
        PUBKKEY = id(pubKey)
        dic = {'documento' : document, 'firma':signature, 'llave_pub' : PUBKKEY }
        return render(request, 'webapp/firmador.html',dic)

    def post(self,request):
        document = request.POST['document']
        signature = firmar(document)
        request.session['document'] = document
        request.session['signature'] = signature
        return redirect(request.path)

def verificar(document,signature):
    if len(document) > 0 and len(signature) >0:
        msg = bytes(document, 'utf-8')
        signature_bytes = bytes.fromhex(signature)
        hash = SHA256.new(msg)
        verifier = PKCS115_SigScheme(pubKey)
        try:
            verifier.verify(hash, signature_bytes)
            return "Signature is valid."
        except:
            return "Signature is invalid."

class VerificadorView(View):
    def get(self,request):
        document = request.session.get('document', False)
        signature = request.session.get('signature', False)
        msg = request.session.get('msg', False)
        ishex = request.session.get('ishex', False)
        PUBKEY = id(pubKey)
        if (document): del (request.session['document'])
        if (signature): del (request.session['signature'])
        if (msg): del (request.session['msg'])
        if (ishex): del (request.session['ishex'])
        dic = {'documento': document, 'firma': signature, 'mensaje': msg, 'llave_pub': PUBKEY, 'hexa': ishex}
        return render(request, 'webapp/verificador.html',dic)

    def post(self,request):
        document = request.POST['document']
        signature = request.POST['signature']
        ishex = all(c in string.hexdigits for c in signature)  # check is the input string is hex
        if ishex:
            msg = verificar(document, signature)
            request.session['msg'] = msg
            request.session['signature'] = signature
        request.session['document'] = document
        request.session['ishex'] = ishex
        return redirect(request.path)
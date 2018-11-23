import os
import re
import sys
import hashlib
import logging
import binascii

from lib import base58
from lib.ecdsa import BadSignatureError, der
from lib.ecdsa.curves import SECP256k1
from lib.ecdsa.keys import SigningKey, VerifyingKey
from lib.ecdsa.util import sigdecode_der, sigencode_der_canonize

from lib.pybitcointools import bitcoin as btctools


PY3 = True if sys.version_info[0] >= 3 else False
HEX = re.compile("^[0-9a-fA-F]$")
BHEX = re.compile(b"^[0-9a-fA-F]$")

COMPRESSED = True
MARKER = "1e"

def basint(e):
	# byte as int conversion
	if not PY3:
		e = ord(e)
	return e

def hexlify(data):
	if PY3 and isinstance(data, str):
		if HEX.match(data):
			return data
		else:
			data = data.encode()
	result = binascii.hexlify(data)
	return str(result.decode() if isinstance(result, bytes) else result)

def unhexlify(data):
	if PY3 and isinstance(data, bytes):
		if BHEX.match(data):
			data = data.decode()
		else:
			return data
	if len(data) % 2:
		data = "0" + data
	result = binascii.unhexlify(data)
	return result if isinstance(result, bytes) else result.encode()


def compressEcdsaPublicKey(pubkey):
	first, last = pubkey[:32], pubkey[32:]
	# check if last digit of second part is even (2%2 = 0, 3%2 = 1)
	even = not bool(basint(last[-1]) % 2)
	return (b"\x02" if even else b"\x03") + first


def uncompressEcdsaPublicKey(pubkey):
	"""
	Uncompressed public key is:
	0x04 + x-coordinate + y-coordinate

	Compressed public key is:
	0x02 + x-coordinate if y is even
	0x03 + x-coordinate if y is odd

	y^2 mod p = (x^3 + 7) mod p

	read more : https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689
	"""
	p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
	y_parity = int(pubkey[:2]) - 2
	x = int(pubkey[2:], 16)
	a = (pow(x, 3, p) + 7) % p
	y = pow(a, (p + 1) // 4, p)
	if y % 2 != y_parity:
		y = -y % p
	# return result as der signature (no 0x04 preffix)
	return '{:x}{:x}'.format(x, y)


def getKeys(secret, seed=None):
	"""
	Generate keyring containing public key, signing and checking keys as
	attribute.

	Keyword arguments:
	secret (str or bytes) -- a human pass phrase
	seed (byte) -- a sha256 sequence bytes (private key actualy)

	Return dict
	"""
	if secret and not isinstance(secret, bytes): secret = secret.encode('utf-8')
	seed = hashlib.sha256(secret).digest() if not seed else seed
	signingKey = SigningKey.from_secret_exponent(
		int(binascii.hexlify(seed), 16),
		SECP256k1,
		hashlib.sha256
	)
	publicKey = signingKey.get_verifying_key().to_string()
	return {
		"publicKey": hexlify(compressEcdsaPublicKey(publicKey) if COMPRESSED else publicKey),
		"privateKey": hexlify(signingKey.to_string()),
	}


def getAddress(publicKey):
	"""
	Computes ARK address from keyring.

	Argument:
	publicKey (str) -- public key string

	Return str
	"""
	ripemd160 = hashlib.new('ripemd160', unhexlify(publicKey)).digest()[:20]
	seed = unhexlify(MARKER) + ripemd160
	return base58.b58encode_check(seed)


def verifySignature(value, publicKey, signature):
	"""
	Verify signature.

	Arguments:
	value (str) -- value as hex string in bytes
	publicKey (str) -- a public key as hex string
	signature (str) -- a signature as hex string

	Return bool
	"""
	return verifySignatureFromBytes(unhexlify(value), publicKey, signature)


def verifySignatureFromBytes(data, publicKey, signature):
	"""
	Verify signature.

	Arguments:
	data (bytes) -- data in bytes
	publicKey (str) -- a public key as hex string
	signature (str) -- a signature as hex string

	Return bool
	"""
	if len(publicKey) == 66:
		publicKey = uncompressEcdsaPublicKey(publicKey)
	verifyingKey = VerifyingKey.from_string(unhexlify(publicKey), SECP256k1, hashlib.sha256)
	try:
		verifyingKey.verify(unhexlify(signature), data, hashlib.sha256, sigdecode_der)
	except (BadSignatureError, der.UnexpectedDER):
		return False
	return True


##############################
## HERE STARTS THE OVERRIDE ##
##############################

def newPrivatekey(uncompressed=False):
	return getKeys(None, hashlib.sha256(os.urandom(256)).digest())["privateKey"]


def newSeed():
	return hexlify(hashlib.sha256(os.urandom(256)).digest())


def hdPrivatekey(seed, child):
	masterkey = btctools.bip32_master_key(seed)
	childkey = btctools.bip32_ckd(masterkey, child % 100000000)  # Too large child id could cause problems
	return getKeys(None, hashlib.sha256(unhexlify(btctools.bip32_extract_key(childkey))).digest())["privateKey"]


def privatekeyToAddress(privatekey):
	try:
		signingKey = SigningKey.from_string(unhexlify(privatekey), SECP256k1, hashlib.sha256)
		return hexlify(compressEcdsaPublicKey(signingKey.get_verifying_key().to_string()))
		# return base58.b58encode_check(publicKey)
	except Exception:
		return False


def sign(data, privatekey):
	signingKey = SigningKey.from_string(unhexlify(privatekey), SECP256k1, hashlib.sha256)
	return hexlify(signingKey.sign_deterministic(
		data if isinstance(data, bytes) else data.encode("utf-8"),
		hashlib.sha256,
		sigencode=sigencode_der_canonize)
	)
signOld = sign


def verify(data, address, sign): 
	# sign is under the form (r, s) so have to put in DER format
	# data should be a bytes
	r, s = sign
	return verifySignatureFromBytes(
		data if isinstance(data, bytes) else data.encode("utf-8"),
		address,
		der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
	)

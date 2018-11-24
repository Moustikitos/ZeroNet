from lib.pybitcointools import bitcoin as btctools
from util.Ark import *


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
	try:
		r, s = sign
		sign = der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
	except:
		pass
	return verifySignatureFromBytes(
		data if isinstance(data, bytes) else data.encode("utf-8"),
		address,
		sign		
	)

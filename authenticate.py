import base64
import requests
import json
import urllib


from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_app_key():
			appkey_string = get_app_key()
			return encrypt_using_public_key(appkey_string)

def encrypt_using_public_key(data):
	backend = default_backend()

	cert = x509.load_der_x509_certificate(
		open("C:\Users\pankaj\PycharmProjects\gst\GSTN_PublicKey.cer").read(),backend)
	public_key = cert.public_key()
	binary_data = public_key.encrypt(bytes(data),padding.PKCS1v15())
	return base64.encodestring(binary_data)

def encrypt_otp(otp=None):
	if otp:
		return encrypt_data(otp)

def encrypt_data (data=None, key=None):
	# ref: http://stackoverflow.com/a/12525165
	BS = 16
	pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
	if data:
		backend = default_backend()
		if not key:
			key = str(get_app_key())
		else:
			key = str(key)
		# ref: http://stackoverflow.com/questions/35203086/encrypt-with-aes-ecb-pksc5-migrating-java-to-python
		cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
		encryptor = cipher.encryptor()
		ct = encryptor.update(str(pad(data))) + encryptor.finalize()
		return base64.encodestring(ct)

def mac256(ent=None, key=None):
	if ent and key:
		h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
		h.update(str(ent))
		ct = h.finalize()
		# return ct
		return base64.b16encode(ct)

def decrypt_data(data=None, key=None):
	unpad = lambda s : s[0:-ord(s[-1])]
	if data and key:
		key = bytes(key) if type(key) != bytes else key 
		data = base64.decodestring(data)
	decryptor = Cipher(
		algorithms.AES(key),
		modes.ECB(),
		backend=default_backend()
	).decryptor()
	return unpad(decryptor.update(data) + decryptor.finalize())

def decode_json_response(out, rek, ek):
	api_ek = decrypt_data(rek, ek);
	return base64.decodestring(decrypt_data(out, api_ek))

def get_app_key():
	if frappe.get_doc("GST API Settings").app_key and frappe.get_doc("GST API Settings").app_key != "":
		return frappe.get_doc("GST API Settings").app_key
	else:
		frappe.throw(_("Please set the GST Taxpayer App Key in GST API Settings"))

def get_otp(url=None, verbose=True):
	if not url:
		url = get_gst_url()

	app_key = generate_app_key().replace("\n","")
	headers = get_auth_headers(app_key)

	payload ={
		"action": "OTPREQUEST",
		"app_key": app_key,
		"username": get_gst_user().gsp_user
	}

	return request_txn(method="POST", url=url, payload=payload, headers=headers, add_txn_header=True)

def authenticate_otp(url=None, otp="102030",verbose=True):
	if not url:
		url = get_gst_url()

	app_key = generate_app_key().replace("\n","")
	headers = get_auth_headers(app_key)


	payload ={
		"action": "AUTHTOKEN",
		"username": get_gst_user().gsp_user,
		"app_key": app_key,
		"otp": encrypt_otp(otp)
	}

	return request_txn(method="POST", url=url, payload=payload, headers=headers, add_txn_header=True)

def extend_auth_token(url=None, auth_token=None, old_sek=None, verbose=True):
	if not url:
		url = get_gst_url()

	if not auth_token:
		frappe.throw(_("auth_token not found"))

	if not old_sek:
		frappe.throw(_("old_sek not found"))

	headers = get_auth_headers()
	decrypted_old_sek = decrypt_data(old_sek,get_app_key())
	payload = {
		"action": "REFRESHTOKEN",
		"app_key": encrypt_data(get_app_key(),decrypted_old_sek),
		"username": get_gst_user().gsp_user.lower(),
		"auth_token": auth_token
	}

	return request_txn(method="POST", url=url, payload=payload, headers=headers, add_txn_header=True)

def get_gst_user():
	try:
		gst_user = frappe.get_doc("GSP User", {"frappe_user":frappe.session.user})
		return gst_user
	except Exception as e:
		frappe.throw("Frappe User has no GSP User associated")

def get_gst_settings():
	gst_settings = frappe.get_doc("GST API Settings")
	return gst_settings

def get_gst_url():
	return "http://devapi.gstsystem.co.in/taxpayerapi/v0.2/authenticate"

def get_auth_headers(app_key=None):
	
	if not app_key:
		app_key = generate_app_key().replace("\n","")
	
	gst_settings = get_gst_settings()
	
	if not gst_settings.clientid or not gst_settings.client_secret:
		frappe.throw("Please enter all the GST Settings")
	headers = {
		'clientid': gst_settings.clientid,
		'client-secret': gst_settings.client_secret,
		'state-cd': get_gst_user().state_code,
		'username': get_gst_user().gsp_user,
		'content-type': "application/json",
	}

	try:
		headers['ip-usr'] = frappe.get_request_header('REMOTE_ADDR')
	except Exception as e:
		headers['ip-usr'] = json.loads(urllib.urlopen("http://ip.jsontest.com/").read())["ip"]

	return headers

def request_txn(method=None, url=None, payload=None, headers=None, add_txn_header=False, verbose=True): 
	
	if not method:
		frappe.throw(_("Please specify request method"))
	
	if not url:
		frappe.throw(_("Please specify request URL"))

	if not headers:
		frappe.throw(_("Please specify request headers"))

	gst_txn = frappe.new_doc("GSTN TXN")
	gst_txn.method = method
	gst_txn.url = url[0:140]
	gst_txn.user = frappe.session.user
	gst_txn.payload = json.dumps(payload)
	gst_txn.save(ignore_permissions=True)

	frappe.db.commit()

	if add_txn_header:
		headers["txn"] = gst_txn.name

	response = requests.request(method, url, data=json.dumps(payload), headers=headers)

	if verbose:
		print response.text
	
	gst_txn.response = response.text
	gst_txn.headers = json.dumps(headers)
	gst_txn.save(ignore_permissions=True)
	frappe.db.commit()

	return response.json()

def decrypt_response(data=None, rek=None, sek=None, app_key=None):
	if not app_key:
		app_key = get_app_key()

	if not rek:
		print ("rek required")
		return

	if not sek:
		print ("sek required")
		return
	
	if not data:
		print ("data required")
		return

	decrypted_rek = decrypt_data(rek, decrypt_data(sek,app_key))
	return base64.decodestring(decrypt_data(data, decrypted_rek))

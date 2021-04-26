/**
 * Do an HTTP Request
 * @private
 */
var _makeRequest = function(opts) {
	return new Promise(function(resolve, reject) {
		var xhr = new XMLHttpRequest();
		xhr.open(opts.method, opts.url);
		xhr.responseType = 'json';
		xhr.onload = function() {
			if (this.status == opts.status) {
				resolve(xhr.response);
			} else {
				reject({
					status: this.status,
					statusText: xhr.statusText,
					response: xhr.response
				});
			}
		};
		xhr.onerror = function() {
			reject({
				status: this.status,
				statusText: xhr.statusText,
				response: xhr.response
			});
		};
		
		if (opts.headers) {
			Object.keys(opts.headers).forEach(function(key) {
				xhr.setRequestHeader(key, opts.headers[key]);
			});
		}

		xhr.send(JSON.stringify(opts.params));
	});
};
	
/**
 * Convert String to Base64
 * @private
 */
var _toBase64 = function(str) {
	return btoa(str);
};

/**
 * Convert Base64 to String
 * @private
 */
var _fromBase64 = function(str) {
	return atob(str);
};

/**
 * Convert String to an ArrayBuffer
 * @private
 */
var _toArrayBuffer = function(str) {
	return Uint8Array.from(str, function(c) { 
		return c.charCodeAt(0);
	});
};

/**
 * Convert an ArrayBuffer to String
 * @private
 */
var _fromArrayBuffer = function(arrayBuffer) {
	return new Uint8Array(arrayBuffer).reduce(function(data, byte) { 
		return data + String.fromCharCode(byte); 
	}, '');
};

var init = async function() {
	// On first run, generate a KeyPair
	const keys = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]);
	
	// Export the generated PublicKey as a Base64 encoded String
	const clientPublicKey = await window.crypto.subtle.exportKey("spki", keys.publicKey);
	const clientPublicKeyExported = _toBase64(_fromArrayBuffer(clientPublicKey));
	
	// Tell the server to send a generated PublicKey, convert to ArrayBuffer and import as a PublicKey
	const serverPublicKey = await _makeRequest({
		method: 'OPTIONS',
		url: './api/rest/exchange',
		status: 200,
		headers: { 'x-public-key': clientPublicKeyExported }
	});
	const serverPublicKeyExported = _toArrayBuffer(_fromBase64(serverPublicKey.publicKey));
	const serverPublicKeyImported = await window.crypto.subtle.importKey("spki", serverPublicKeyExported, { name: "ECDH", namedCurve: "P-384" }, true, []);
	
	// Generate the SecretKey for data transmission
	const secretKey = await window.crypto.subtle.deriveKey({ name: "ECDH", public: serverPublicKeyImported }, keys.privateKey, { name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
	
	console.log("GET");
	getData(secretKey);
	
	console.log("POST");
	postData(secretKey);
}

var getData = async function(secretKey) {
	const dataEncrypted = await _makeRequest({
		method: 'GET',
		url: './api/rest/exchange',
		status: 200
	});
	console.log(dataEncrypted);
	
	const dataDecrypted = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: _toArrayBuffer(_fromBase64(dataEncrypted.iv)) }, secretKey, _toArrayBuffer(_fromBase64(dataEncrypted.text)));
	console.log(_fromArrayBuffer(dataDecrypted));
};

var postData = async function(secretKey) {
	const text = "Salut le monde";
	const iv = window.crypto.getRandomValues(new Uint8Array(16));
	const cipherText = await window.crypto.subtle.encrypt({ name: "AES-CBC", iv: iv }, secretKey, _toArrayBuffer(text));
	
	const dataEncrypted = await _makeRequest({
		method: 'POST',
		url: './api/rest/exchange',
		status: 200,
		headers: { 'Content-Type': 'application/json' },
		params : { iv: _toBase64(_fromArrayBuffer(iv)), text : _toBase64(_fromArrayBuffer(cipherText)) }
	});
	console.log(dataEncrypted);
	
	const dataDecrypted = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv: _toArrayBuffer(_fromBase64(dataEncrypted.iv)) }, secretKey, _toArrayBuffer(_fromBase64(dataEncrypted.text)));
	console.log(_fromArrayBuffer(dataDecrypted));
};

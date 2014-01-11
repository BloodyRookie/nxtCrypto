
hexchars = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

/* Two all purpose helper functions follow */
/* string_to_array: convert a string to a character (byte) array */
function string_to_byteArray(str) 
{
    var len = str.length;
    var res = new Array(len);
    for(var i = 0; i < len; i++)
    {
        res[i] = str.charCodeAt(i);
    }
    return res;
}

/* array_to_hex_string: convert a short array to a hexadecimal string */
function shortArray_to_hex_string(ary) 
{
    var res = "";
    for(var i = 0; i < ary.length; i++)
    {
        res += hexchars[(ary[i] >> 4) & 0x0f] + hexchars[ary[i] & 0x0f] + hexchars[(ary[i] >> 12) & 0x0f] + hexchars[(ary[i] >> 8) & 0x0f];
    }
    return res;
}

/* array_to_hex_string: convert a byte array to a hexadecimal string */
function byteArray_to_hex_string(ary) 
{
	var val;
    var res = "";
    for(var i = 0; i < ary.length; i++)
    {
    	val = ary[i];
    	if (val < 0)
    	{
    		val += 256;
    	}
        res += hexchars[val >> 4] + hexchars[val & 0x0f];
    }
    return res;
}

function byteArrayToShortArray(byteArray)
{
	shortArray = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	var i;
	for (i=0; i<16; i++)
	{
		//shortArray[i] = byteArray[31-i*2] | byteArray[30-i*2] << 8;
		shortArray[i] = byteArray[i*2] | byteArray[i*2+1] << 8;
	}
	return shortArray;
}

function shortArrayToByteArray(shortArray)
{
	byteArray = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	var i;
	for (i=0; i<16; i++)
	{
		//byteArray[2*i] = shortArray[15-i] >> 8;
		//byteArray[2*i+1] = shortArray[15-i] & 0xff;
		byteArray[2*i] = shortArray[i] & 0xff;
		byteArray[2*i+1] = shortArray[i] >> 8;
	}
	
	return byteArray;
}

function toInt8Array(array)
{
	result = new Int8Array(array.length);
	for (i=0; i<array.length; i++)
	{
		result[i] = array[i];
	}
	
	return result;
}

function getPublicKey(secretPhrase) 
{
	var publicKey = new Int8Array(32);
	var digest = SHA256_hash(secretPhrase);
	var curve = byteArrayToShortArray(digest);
	var publicKey = curve25519_keygen(null,	curve);
	var publicKeyString = byteArray_to_hex_string(shortArrayToByteArray(publicKey));

	return publicKeyString;
}
/*
 * @param1  {Int8Array} message [in]
 * @param2  {String} secretPhrase [in]
 * @return  {Int8Array[64]}
 */
function sign(message, secretPhrase) 
{
	var ss = new Array(16);
	var secretPhraseBytes = SHA256_hash(secretPhrase);
	curve = byteArrayToShortArray(secretPhraseBytes);
	var PP = curve25519_keygen(ss, curve);
	var P = shortArrayToByteArray(PP);
	var s = shortArrayToByteArray(ss);
	addText("P=" + byteArray_to_hex_string(P))
	addText("s=" + byteArray_to_hex_string(s))
	
	var m = SHA256_hash(message);
	addText("m=" + byteArray_to_hex_string(m))
	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(s, s.length);
	var x = SHA256_finalize();
	addText("x=" + byteArray_to_hex_string(x))
	//sha256_init();
	//var hash = sha256_digest2(m.concat(s));
	//addText("hash=" + byteArray_to_hex_string(hash))
	var xx = byteArrayToShortArray(x)
	var YY = curve25519_keygen(null, xx);
	x = shortArrayToByteArray(xx);
	var Y = shortArrayToByteArray(YY);
	addText("Y=" + byteArray_to_hex_string(Y))

	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(Y, Y.length);
	var h = SHA256_finalize();
	var v = new Int8Array(32);
	var h1 = toInt8Array(h);
	var x1 = toInt8Array(x);
	var s1 = toInt8Array(s);
	addText("h=" + byteArray_to_hex_string(h))
	addText("x=" + byteArray_to_hex_string(x))
	addText("s=" + byteArray_to_hex_string(s))
	curve25519_sign(v, h1, x1, s1);

	var signature = new Int8Array(64);
	for (i=0; i<32; i++)
	{
		signature[i] = v[i];
		signature[i+32] = h1[i];
	}
	var signatureString = byteArray_to_hex_string(signature);
	return signatureString;
}

/*
 * @param1  {Int8Array} signature [in]
 * @param2  {Int8Array} message [in]
 * @param2  {Int8Array} publicKey [in]
 * @return  {Boolean}
 */
function verify(signature, message, publicKey) 
{
	var Y = new Array(32);
	var v = new Int8Array(32);
	var h = new Int8Array(32);

	for (i=0; i<32; i++)
	{
		v[i] = signature[i];
		h[i] = signature[i+32];
	}
	//verify2(Y, v, h, publicKey);
	//addText("Y=" + bytesToHex(Y))

	var m = SHA256_hash(message);
	//addText("message=" + bytesToHex(message))
	//addText("m=" + bytesToHex(m))
	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(Y, Y.length);
	h2 = SHA256_finalize();
	//addText("h=" + bytesToHex(h))
	//addText("h2=" + bytesToHex(h2))
	//sha256_init();
	//sha256_update2(message);
	//h2 = sha256_digest2(Y);

	return arraysEqual(h, toInt8Array(h2));
}

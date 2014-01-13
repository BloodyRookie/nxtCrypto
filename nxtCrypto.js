/* Two all purpose helper functions follow */

/* string_to_array: convert a string to a character (byte) array */

function string_to_array(str) {
    var len = str.length;
    var res = new Array(len);
    for(var i = 0; i < len; i++)
        res[i] = str.charCodeAt(i);
    return res;
}

/* array_to_hex_string: convert a byte array to a hexadecimal string */
function array_to_hex_string(ary) {
    var res = "";
    for(var i = 0; i < ary.length; i++)
        res += SHA256_hexchars[ary[i] >> 4] + SHA256_hexchars[ary[i] & 0x0f];
    return res;
}

/******************************************************************************/

/* The following are the SHA256 routines */

/*
SHA256_init: initialize the internal state of the hash function. Call this
function before calling the SHA256_write function.
*/

function SHA256_init() {
    SHA256_H = new Array(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
    SHA256_buf = new Array();
    SHA256_len = 0;
}

/*
SHA256_write: add a message fragment to the hash function's internal state.
'msg' may be given as string or as byte array and may have arbitrary length.

*/

function SHA256_write(msg) {
    if (typeof(msg) == "string")
        SHA256_buf = SHA256_buf.concat(string_to_array(msg));
    else
        SHA256_buf = SHA256_buf.concat(msg);
    for(var i = 0; i + 64 <= SHA256_buf.length; i += 64)
        SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf.slice(i, i + 64));
    SHA256_buf = SHA256_buf.slice(i);
    SHA256_len += msg.length;
}

/*
SHA256_finalize: finalize the hash value calculation. Call this function
after the last call to SHA256_write. An array of 32 bytes (= 256 bits)
is returned.
*/

function SHA256_finalize() {
    SHA256_buf[SHA256_buf.length] = 0x80;

    if (SHA256_buf.length > 64 - 8) {
        for(var i = SHA256_buf.length; i < 64; i++)
            SHA256_buf[i] = 0;
        SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf);
        SHA256_buf.length = 0;
    }

    for(var i = SHA256_buf.length; i < 64 - 5; i++)
        SHA256_buf[i] = 0;
    SHA256_buf[59] = (SHA256_len >>> 29) & 0xff;
    SHA256_buf[60] = (SHA256_len >>> 21) & 0xff;
    SHA256_buf[61] = (SHA256_len >>> 13) & 0xff;
    SHA256_buf[62] = (SHA256_len >>> 5) & 0xff;
    SHA256_buf[63] = (SHA256_len << 3) & 0xff;
    SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf);

    var res = new Array(32);
    for(var i = 0; i < 8; i++) {
        res[4 * i + 0] = SHA256_H[i] >>> 24;
        res[4 * i + 1] = (SHA256_H[i] >> 16) & 0xff;
        res[4 * i + 2] = (SHA256_H[i] >> 8) & 0xff;
        res[4 * i + 3] = SHA256_H[i] & 0xff;
    }

    delete SHA256_H;
    delete SHA256_buf;
    delete SHA256_len;
    return res;
}

/*
SHA256_hash: calculate the hash value of the string or byte array 'msg'
and return it as hexadecimal string. This shortcut fu?ction may be more
convenient than calling SHA256_init, SHA256_write, SHA256_finalize
and array_to_hex_string explicitly.
*/

function SHA256_hash(msg) {
    var res;
    SHA256_init();
    SHA256_write(msg);
    return SHA256_finalize();
}


/******************************************************************************/

/* The following lookup tables and functions are for internal use only! */

SHA256_hexchars = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f');

SHA256_K = new Array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

function SHA256_sigma0(x) {
    return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
}

function SHA256_sigma1(x) {
    return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
}

function SHA256_Sigma0(x) {
    return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^
        ((x >>> 22) | (x << 10));
}

function SHA256_Sigma1(x) {
    return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^
        ((x >>> 25) | (x << 7));
}

function SHA256_Ch(x, y, z) {
    return z ^ (x & (y ^ z));
}

function SHA256_Maj(x, y, z) {
    return (x & y) ^ (z & (x ^ y));
}

function SHA256_Hash_Word_Block(H, W) {
    for(var i = 16; i < 64; i++)
        W[i] = (SHA256_sigma1(W[i - 2]) + W[i - 7] +
            SHA256_sigma0(W[i - 15]) + W[i - 16]) & 0xffffffff;
    var state = new Array().concat(H);
    for(var i = 0; i < 64; i++) {
        var T1 = state[7] + SHA256_Sigma1(state[4]) +
            SHA256_Ch(state[4], state[5], state[6]) + SHA256_K[i] + W[i];
        var T2 = SHA256_Sigma0(state[0]) + SHA256_Maj(state[0], state[1], state[2]);
        state.pop();
        state.unshift((T1 + T2) & 0xffffffff);
        state[4] = (state[4] + T1) & 0xffffffff;
    }
    for(var i = 0; i < 8; i++)
        H[i] = (H[i] + state[i]) & 0xffffffff;
}

function SHA256_Hash_Byte_Block(H, w) {
    var W = new Array(16);
    for(var i = 0; i < 16; i++)
        W[i] = w[4 * i + 0] << 24 | w[4 * i + 1] << 16 |
            w[4 * i + 2] << 8 | w[4 * i + 3];
    SHA256_Hash_Word_Block(H, W);
}


/** Crypto functions **/
function getPublicKey(secretPhrase) 
{
	var publicKey = new Int8Array(32);
	var digest = SHA256_hash(secretPhrase);
	var curve = byteArrayToShortArray(digest);
	var publicKey = curve25519_keygen(null,	curve);
	var publicKeyString = byteArray_to_hex_string(shortArrayToByteArray(publicKey));

	return publicKeyString;
}

function sign(message, secretPhrase) 
{
	var ss = new Array(16);
	var secretPhraseBytes = SHA256_hash(secretPhrase);
	curve = byteArrayToShortArray(secretPhraseBytes);
	var PP = curve25519_keygen(ss, curve);
	var P = shortArrayToByteArray(PP);
	var s = shortArrayToByteArray(ss);
	
	var m = SHA256_hash(message);
	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(s, s.length);
	var x = SHA256_finalize();
	var xx = byteArrayToShortArray(x)
	var YY = curve25519_keygen(null, xx);
	x = shortArrayToByteArray(xx);
	var Y = shortArrayToByteArray(YY);

	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(Y, Y.length);
	var h = SHA256_finalize();
	var v = new Int8Array(32);
	var h1 = toInt8Array(h);
	var x1 = toInt8Array(x);
	var s1 = toInt8Array(s);
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

function verify(signature, message, publicKey) 
{
	var Y = new Int8Array(32);
	var v = new Int8Array(32);
	var h = new Int8Array(32);

	var sig = hexstring_to_byteArray(signature);
	var msg = hexstring_to_byteArray(message);
	var pKey = hexstring_to_byteArray(publicKey);
	for (i=0; i<32; i++)
	{
		v[i] = sig[i];
		h[i] = sig[i+32];
	}
	curve25519_verify(Y, v, h, pKey);
	var YY = fromInt8Array(Y);
	var m = SHA256_hash(msg);
	SHA256_init();
	SHA256_write(m, m.length);
	SHA256_write(YY, YY.length);
	h2 = SHA256_finalize();

	return arraysEqual(h, toInt8Array(h2));
}

/** Curve 25519 implementation **/
curve25519_zero = function() {
  return [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
}

curve25519_one = function() {
  return [1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
}

curve25519_nine = function() {
  return [9,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
}

curve25519_r2y = function() {
	  return [0x1670,0x4000,0xf219,0xd369,0x2248,0x4845,0x679a,0x884d,0x5d19,0x16bf,0xda74,0xe57d,0x5e53,0x3705,0x3526,0x17c0];
}

curve25519_2y = function() {
	  return [0x583b,0x0262,0x74bb,0xac2c,0x3c9b,0x2507,0x6503,0xdb85,0x5d66,0x116e,0x45a7,0x3fc2,0xf296,0x8ebe,0xccbc,0x3ea3];
}

curve25519_clamp = function(curve) {
  curve[0] &= 0xFFF8;
  curve[15] &= 0x7FFF;
  curve[15] |= 0x4000;
  return curve;
}

curve25519_clamp_string = function(s) {
  return curve25519_to8bitString(curve25519_clamp(curve25519_from8bitString(s)));
}

curve25519_getbit = function(curve, c) {
  return Math.floor(curve[Math.floor(c / 16)] / Math.pow(2, c % 16)) % 2;
}
  
curve25519_from8bitString = function(s) {
  var curve = curve25519_zero();
  if (32 != s.length)
    throw "curve25519_fromString(): input string must exactly be 32 bytes";
  for(var i = 0; i < 16; ++i)
    curve[i] = s.charCodeAt(31-i*2) | (s.charCodeAt(30-i*2) << 8);
  return curve;
}

curve25519_to8bitString = function(curve) {
  var s = "";
  for(var i = 15; i >= 0; --i)
    s += String.fromCharCode(((curve[i] >>> 8) & 0xFF), (curve[i] & 0xFF));
  return s;
}

curve25519_prime = [0xffff-18, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff];

/* group order (a prime near 2^252+2^124) */
curve25519_order = [
	    237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];

curve25519_order_times_8 = [
	    104, 159, 174, 231, 210, 24, 147, 192, 178, 230, 188, 23, 245, 206, 247, 166,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128];


curve25519_convertToByteArray = function(a) {
	var b = new Int8Array(32);
	var i;
	for (i=0; i<16; i++)
	{
		b[2*i] = a[i] & 0xff;
		b[2*i+1] = a[i] >> 8;
	}
	
	return b;
}

curve25519_convertToShortArray = function(a) {
	var b = new Array(16);
	var i, val1, val2;
	for (i=0; i<16; i++)
	{
		val1 = a[i*2];
		if (val1 < 0)
		{
			val1 +=256;
		}
		val2 = a[i*2+1];
		if (val2 < 0)
		{
			val2 +=256;
		}
		b[i] = val1 + val2*256;
	}
	return b;
	
}

curve25519_fillShortArray = function(src, dest) {
	var i;
	for (i=0; i<16; i++)
	{
		dest[i] = src[i];
	}
}

curve25519_fillByteArray = function(src, dest) {
	var i;
	for (i=0; i<32; i++)
	{
		dest[i] = src[i];
	}
}

curve25519_log16 = function(text, a) {
	var b = shortArray_to_hex_string(a);
	addText(text + b);
}

curve25519_log32 = function(text, a) {
	var b = byteArray_to_hex_string(a);
	addText(text + b);
}

curve25519_cpy32 = function(a) {
	var b = new Int8Array(32);
	for (i = 0; i < 32; i++)
	{
		b[i] = a[i];
	}
	return b;
}

curve25519_mula_small = function(p, q, m, x, n, z) {
	v=0;
	for (j=0; j<n; ++j) 
	{
		v += (q[j+m] & 0xFF) + z * (x[j] & 0xFF);
		p[j+m] = (v & 0xFF);
		v >>= 8;
	}
	return v;		
}

curve25519_mula32 = function(p, x, y, t, z) {
	n = 31;
	w = 0;
	for (i=0; i < t; i++) 
	{
		zy = z * (y[i] & 0xFF);
		w += curve25519_mula_small(p, p, i, x, n, zy) + (p[i+n] & 0xFF) + zy * (x[n] & 0xFF);
		p[i+n] = (w & 0xFF);
		w >>= 8;
	}
	p[i+n] = ((w + (p[i+n] & 0xFF)) & 0xFF);
	return w >> 8;
}

curve25519_divmod = function(q, r, n, d, t) {
	rn = 0;
	dt = ((d[t-1] & 0xFF) << 8);
	if (t>1) 
	{
		dt |= (d[t-2] & 0xFF);
	}
	while (n-- >= t) 
	{
		z = (rn << 16) | ((r[n] & 0xFF) << 8);
		if (n>0) 
		{
			z |= (r[n-1] & 0xFF);
		}
		z = parseInt(z/dt);
		rn += curve25519_mula_small(r,r, n-t+1, d, t, -z);
		q[n-t+1] = ((z + rn) & 0xFF); // rn is 0 or -1 (underflow)
		curve25519_mula_small(r,r, n-t+1, d, t, -rn);
		rn = (r[n] & 0xFF);
		r[n] = 0;
	}
	r[t-1] = (rn & 0xFF);
}

curve25519_numsize = function(x, n)  {
	while (n--!=0 && x[n]==0)
		;
	return n+1;
}

curve25519_egcd32 = function(x, y, a, b) {
	an = 0; bn = 32; qn=0; i=0;
	for (i = 0; i < 32; i++)
	{
		x[i] = y[i] = 0;
	}
	x[0] = 1;
	an = curve25519_numsize(a, 32);
	if (an==0)
	{
		return y;	// division by zero
	}
	temp=new Int8Array(32);
	while (true) 
	{
		qn = bn - an + 1;
		curve25519_divmod(temp, b, bn, a, an);
		bn = curve25519_numsize(b, bn);
		if (bn==0)
		{
			return x;
		}
		curve25519_mula32(y, x, temp, qn, -1);

		qn = an - bn + 1;
		curve25519_divmod(temp, a, an, b, bn);
		an = curve25519_numsize(a, an);
		if (an==0)
		{
			return y;
		}
		curve25519_mula32(x, y, temp, qn, -1);
	}
}

curve25519_compare = function (a ,b) {
  var c;
  for (c = 15; c >= 0; c--) {
    var x = a[c];
    var y = b[c];
    if (x > y) {
      return 1;
    }
    if (x < y) {
      return -1;
    }
  }
  return 0;
}

curve25519_cpy16 = function(a) {
	var r = [];
	var i;
	for (i=0; i<16;i++)
	{
		r[i] = a[i];
	}
	return r;
}

curve25519_isNegative = function(x) {
	return curve25519_compare(x, 0)<0? 1 : 0;
}

curve25519_add = function (a, b) {
  var r = [];
  var v;
  r[0] = (v = a[0] + b[0]) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + a[1] + b[1]) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + a[2] + b[2]) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + a[3] + b[3]) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + a[4] + b[4]) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + a[5] + b[5]) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + a[6] + b[6]) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + a[7] + b[7]) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + a[8] + b[8]) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + a[9] + b[9]) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + a[10] + b[10]) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + a[11] + b[11]) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + a[12] + b[12]) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + a[13] + b[13]) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + a[14] + b[14]) % 0x10000;
  r[15] = Math.floor(v / 0x10000) + a[15] + b[15];
  return r;
}

curve25519_subtract = function (a, b) {
  var r = [];
  var v;
  r[0] = (v = 0x80000 + a[0] - b[0]) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[1] - b[1]) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[2] - b[2]) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[3] - b[3]) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[4] - b[4]) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[5] - b[5]) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[6] - b[6]) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[7] - b[7]) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[8] - b[8]) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[9] - b[9]) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[10] - b[10]) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[11] - b[11]) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[12] - b[12]) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[13] - b[13]) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[14] - b[14]) % 0x10000;
  r[15] = Math.floor(v / 0x10000) - 8 + a[15] - b[15];
  return r;
}

curve25519_sqr = function(a) {
	  var x = curve25519_sqr8h(a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]);
	  var z = curve25519_sqr8h(a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]);
	  var y = curve25519_sqr8h(a[15] + a[7], a[14] + a[6], a[13] + a[5], a[12] + a[4], a[11] + a[3], a[10] + a[2], a[9] + a[1], a[8] + a[0]);
	  var r = [];
	  var v;
	  r[0] = (v = 0x800000 + z[0] + (y[8] -x[8] -z[8] + x[0] -0x80) * 38) % 0x10000;
	  r[1] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[1] + (y[9] -x[9] -z[9] + x[1]) * 38) % 0x10000;
	  r[2] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[2] + (y[10] -x[10] -z[10] + x[2]) * 38) % 0x10000;
	  r[3] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[3] + (y[11] -x[11] -z[11] + x[3]) * 38) % 0x10000;
	  r[4] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[4] + (y[12] -x[12] -z[12] + x[4]) * 38) % 0x10000;
	  r[5] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[5] + (y[13] -x[13] -z[13] + x[5]) * 38) % 0x10000;
	  r[6] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[6] + (y[14] -x[14] -z[14] + x[6]) * 38) % 0x10000;
	  r[7] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[7] + (y[15] -x[15] -z[15] + x[7]) * 38) % 0x10000;
	  r[8] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[8] + y[0] -x[0] -z[0] + x[8] * 38) % 0x10000;
	  r[9] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[9] + y[1] -x[1] -z[1] + x[9] * 38) % 0x10000;
	  r[10] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[10] + y[2] -x[2] -z[2] + x[10] * 38) % 0x10000;
	  r[11] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[11] + y[3] -x[3] -z[3] + x[11] * 38) % 0x10000;
	  r[12] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[12] + y[4] -x[4] -z[4] + x[12] * 38) % 0x10000;
	  r[13] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[13] + y[5] -x[5] -z[5] + x[13] * 38) % 0x10000;
	  r[14] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[14] + y[6] -x[6] -z[6] + x[14] * 38) % 0x10000;
	  r[15] = 0x7fff80 + Math.floor(v / 0x10000) + z[15] + y[7] -x[7] -z[7] + x[15] * 38;
	  return r;
	}

curve25519_mul = function(a, b) {
	  // Karatsuba multiplication scheme: x*y = (b^2+b)*x1*y1 - b*(x1-x0)*(y1-y0) + (b+1)*x0*y0
	  var x = curve25519_mul8h(a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8], b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]);
	  var z = curve25519_mul8h(a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0], b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]);
	  var y = curve25519_mul8h(a[15] + a[7], a[14] + a[6], a[13] + a[5], a[12] + a[4], a[11] + a[3], a[10] + a[2], a[9] + a[1], a[8] + a[0],
	                          b[15] + b[7], b[14] + b[6], b[13] + b[5], b[12] + b[4], b[11] + b[3], b[10] + b[2], b[9] + b[1], b[8] + b[0]);
	  var r = [];
	  var v;
	  r[0] = (v = 0x800000 + z[0] + (y[8] -x[8] -z[8] + x[0] -0x80) * 38) % 0x10000;
	  r[1] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[1] + (y[9] -x[9] -z[9] + x[1]) * 38) % 0x10000;
	  r[2] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[2] + (y[10] -x[10] -z[10] + x[2]) * 38) % 0x10000;
	  r[3] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[3] + (y[11] -x[11] -z[11] + x[3]) * 38) % 0x10000;
	  r[4] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[4] + (y[12] -x[12] -z[12] + x[4]) * 38) % 0x10000;
	  r[5] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[5] + (y[13] -x[13] -z[13] + x[5]) * 38) % 0x10000;
	  r[6] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[6] + (y[14] -x[14] -z[14] + x[6]) * 38) % 0x10000;
	  r[7] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[7] + (y[15] -x[15] -z[15] + x[7]) * 38) % 0x10000;
	  r[8] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[8] + y[0] -x[0] -z[0] + x[8] * 38) % 0x10000;
	  r[9] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[9] + y[1] -x[1] -z[1] + x[9] * 38) % 0x10000;
	  r[10] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[10] + y[2] -x[2] -z[2] + x[10] * 38) % 0x10000;
	  r[11] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[11] + y[3] -x[3] -z[3] + x[11] * 38) % 0x10000;
	  r[12] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[12] + y[4] -x[4] -z[4] + x[12] * 38) % 0x10000;
	  r[13] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[13] + y[5] -x[5] -z[5] + x[13] * 38) % 0x10000;
	  r[14] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[14] + y[6] -x[6] -z[6] + x[14] * 38) % 0x10000;
	  r[15] = 0x7fff80 + Math.floor(v / 0x10000) + z[15] + y[7] -x[7] -z[7] + x[15] * 38;
	  return r;
	}

curve25519_sqr8h = function (a7, a6, a5, a4, a3, a2, a1, a0) {
  var r = [];
  var v;
  r[0] = (v = a0*a0) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + 2*a0*a1) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + 2*a0*a2 + a1*a1) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + 2*a0*a3 + 2*a1*a2) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + 2*a0*a4 + 2*a1*a3 + a2*a2) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + 2*a0*a5 + 2*a1*a4 + 2*a2*a3) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + 2*a0*a6 + 2*a1*a5 + 2*a2*a4 + a3*a3) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + 2*a0*a7 + 2*a1*a6 + 2*a2*a5 + 2*a3*a4) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + 2*a1*a7 + 2*a2*a6 + 2*a3*a5 + a4*a4) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + 2*a2*a7 + 2*a3*a6 + 2*a4*a5) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + 2*a3*a7 + 2*a4*a6 + a5*a5) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + 2*a4*a7 + 2*a5*a6) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + 2*a5*a7 + a6*a6) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + 2*a6*a7) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + a7*a7) % 0x10000;
  r[15] = Math.floor(v / 0x10000);
  return r;
}

curve25519_sqrmodp = function(a) {
  var x = curve25519_sqr8h(a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]);
  var z = curve25519_sqr8h(a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]);
  var y = curve25519_sqr8h(a[15] + a[7], a[14] + a[6], a[13] + a[5], a[12] + a[4], a[11] + a[3], a[10] + a[2], a[9] + a[1], a[8] + a[0]);
  var r = [];
  var v;
  r[0] = (v = 0x800000 + z[0] + (y[8] -x[8] -z[8] + x[0] -0x80) * 38) % 0x10000;
  r[1] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[1] + (y[9] -x[9] -z[9] + x[1]) * 38) % 0x10000;
  r[2] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[2] + (y[10] -x[10] -z[10] + x[2]) * 38) % 0x10000;
  r[3] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[3] + (y[11] -x[11] -z[11] + x[3]) * 38) % 0x10000;
  r[4] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[4] + (y[12] -x[12] -z[12] + x[4]) * 38) % 0x10000;
  r[5] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[5] + (y[13] -x[13] -z[13] + x[5]) * 38) % 0x10000;
  r[6] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[6] + (y[14] -x[14] -z[14] + x[6]) * 38) % 0x10000;
  r[7] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[7] + (y[15] -x[15] -z[15] + x[7]) * 38) % 0x10000;
  r[8] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[8] + y[0] -x[0] -z[0] + x[8] * 38) % 0x10000;
  r[9] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[9] + y[1] -x[1] -z[1] + x[9] * 38) % 0x10000;
  r[10] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[10] + y[2] -x[2] -z[2] + x[10] * 38) % 0x10000;
  r[11] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[11] + y[3] -x[3] -z[3] + x[11] * 38) % 0x10000;
  r[12] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[12] + y[4] -x[4] -z[4] + x[12] * 38) % 0x10000;
  r[13] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[13] + y[5] -x[5] -z[5] + x[13] * 38) % 0x10000;
  r[14] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[14] + y[6] -x[6] -z[6] + x[14] * 38) % 0x10000;
  r[15] = 0x7fff80 + Math.floor(v / 0x10000) + z[15] + y[7] -x[7] -z[7] + x[15] * 38;
  curve25519_reduce(r);
  return r;
}

curve25519_mul8h = function(a7, a6, a5, a4, a3, a2, a1, a0, b7, b6, b5, b4, b3, b2, b1, b0) {
  var r = [];
  var v;
  r[0] = (v = a0*b0) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + a0*b1 + a1*b0) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + a0*b2 + a1*b1 + a2*b0) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + a0*b3 + a1*b2 + a2*b1 + a3*b0) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + a4*b7 + a5*b6 + a6*b5 + a7*b4) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + a5*b7 + a6*b6 + a7*b5) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + a6*b7 + a7*b6) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + a7*b7) % 0x10000;
  r[15] = Math.floor(v / 0x10000);
  return r;
}

curve25519_mulmodp = function(a, b) {
  var x = curve25519_mul8h(a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8], b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]);
  var z = curve25519_mul8h(a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0], b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]);
  var y = curve25519_mul8h(a[15] + a[7], a[14] + a[6], a[13] + a[5], a[12] + a[4], a[11] + a[3], a[10] + a[2], a[9] + a[1], a[8] + a[0],
                          b[15] + b[7], b[14] + b[6], b[13] + b[5], b[12] + b[4], b[11] + b[3], b[10] + b[2], b[9] + b[1], b[8] + b[0]);
  var r = [];
  var v;
  r[0] = (v = 0x800000 + z[0] + (y[8] -x[8] -z[8] + x[0] -0x80) * 38) % 0x10000;
  r[1] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[1] + (y[9] -x[9] -z[9] + x[1]) * 38) % 0x10000;
  r[2] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[2] + (y[10] -x[10] -z[10] + x[2]) * 38) % 0x10000;
  r[3] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[3] + (y[11] -x[11] -z[11] + x[3]) * 38) % 0x10000;
  r[4] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[4] + (y[12] -x[12] -z[12] + x[4]) * 38) % 0x10000;
  r[5] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[5] + (y[13] -x[13] -z[13] + x[5]) * 38) % 0x10000;
  r[6] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[6] + (y[14] -x[14] -z[14] + x[6]) * 38) % 0x10000;
  r[7] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[7] + (y[15] -x[15] -z[15] + x[7]) * 38) % 0x10000;
  r[8] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[8] + y[0] -x[0] -z[0] + x[8] * 38) % 0x10000;
  r[9] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[9] + y[1] -x[1] -z[1] + x[9] * 38) % 0x10000;
  r[10] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[10] + y[2] -x[2] -z[2] + x[10] * 38) % 0x10000;
  r[11] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[11] + y[3] -x[3] -z[3] + x[11] * 38) % 0x10000;
  r[12] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[12] + y[4] -x[4] -z[4] + x[12] * 38) % 0x10000;
  r[13] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[13] + y[5] -x[5] -z[5] + x[13] * 38) % 0x10000;
  r[14] = (v = 0x7fff80 + Math.floor(v / 0x10000) + z[14] + y[6] -x[6] -z[6] + x[14] * 38) % 0x10000;
  r[15] = 0x7fff80 + Math.floor(v / 0x10000) + z[15] + y[7] -x[7] -z[7] + x[15] * 38;
  curve25519_reduce(r);
  return r;
}

curve25519_reduce = function (a) {
  var v = a[15];
  if (v < 0x8000) return;
  a[15] = v % 0x8000;
  v = Math.floor(v / 0x8000) * 19;
  a[0] = (v += a[0]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[1] = (v += a[1]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[2] = (v += a[2]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[3] = (v += a[3]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[4] = (v += a[4]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[5] = (v += a[5]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[6] = (v += a[6]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[7] = (v += a[7]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[8] = (v += a[8]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[9] = (v += a[9]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[10] = (v += a[10]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[11] = (v += a[11]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[12] = (v += a[12]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[13] = (v += a[13]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[14] = (v += a[14]) % 0x10000;
  if ((v = Math.floor(v / 0x10000)) < 1) return;
  a[15] += v;
}

curve25519_addmodp = function(a, b) {
  var r = [];
  var v;
  r[0] = (v = (Math.floor(a[15] / 0x8000) + Math.floor(b[15] / 0x8000)) * 19 + a[0] + b[0]) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + a[1] + b[1]) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + a[2] + b[2]) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + a[3] + b[3]) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + a[4] + b[4]) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + a[5] + b[5]) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + a[6] + b[6]) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + a[7] + b[7]) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + a[8] + b[8]) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + a[9] + b[9]) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + a[10] + b[10]) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + a[11] + b[11]) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + a[12] + b[12]) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + a[13] + b[13]) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + a[14] + b[14]) % 0x10000;
  r[15] = Math.floor(v / 0x10000) + a[15] % 0x8000 + b[15] % 0x8000;
  return r;
}

curve25519_submodp = function(a, b) {
  var r = [];
  var v;
  r[0] = (v = 0x80000 + (Math.floor(a[15] / 0x8000) - Math.floor(b[15] / 0x8000) - 1) * 19 + a[0] - b[0]) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[1] - b[1]) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[2] - b[2]) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[3] - b[3]) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[4] - b[4]) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[5] - b[5]) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[6] - b[6]) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[7] - b[7]) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[8] - b[8]) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[9] - b[9]) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[10] - b[10]) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[11] - b[11]) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[12] - b[12]) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[13] - b[13]) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + 0x7fff8 + a[14] - b[14]) % 0x10000;
  r[15] = Math.floor(v / 0x10000) + 0x7ff8 + a[15]%0x8000 - b[15]%0x8000;
  return r;
}

curve25519_invmodp = function (a) {
	  var c = a;
	  var i = 250;
	  while (--i) {
		a = curve25519_sqrmodp(a);
	    a = curve25519_mulmodp(a, c);
	  }
	  a = curve25519_sqrmodp(a);
	  a = curve25519_sqrmodp(a); 
	  a = curve25519_mulmodp(a, c);
	  a = curve25519_sqrmodp(a);
	  a = curve25519_sqrmodp(a); 
	  a = curve25519_mulmodp(a, c);
	  a = curve25519_sqrmodp(a); 
	  a = curve25519_mulmodp(a, c);
	  return a;
	}

curve25519_invmodp2 = function (a) {
	  var c = a;
	  var i = 250;
	  while (--i) {
		a = curve25519_sqrmodp(a);
	    a = curve25519_mulmodp(a, c);
	  }
	  a = curve25519_sqrmodp(a);
	  a = curve25519_sqrmodp(a); 
	  a = curve25519_mulmodp(a, c);
	  return a;
	}

curve25519_sqrtmodp = function(x) {
	
	var t1 = curve25519_addmodp(x,x);
	var v = curve25519_invmodp2(t1);
	var t2 = curve25519_sqrmodp(v);
	t2 = curve25519_mulmodp(t1, t2);
	t2 = curve25519_subtract(t2, curve25519_one());
	t1 = curve25519_mulmodp(v, t2);
	t2 = curve25519_mulmodp(x, t1);
	return t2;
}

curve25519_mulasmall = function(a, m) {
  var r = [];
  var v;
  r[0] = (v = a[0] * m) % 0x10000;
  r[1] = (v = Math.floor(v / 0x10000) + a[1]*m) % 0x10000;
  r[2] = (v = Math.floor(v / 0x10000) + a[2]*m) % 0x10000;
  r[3] = (v = Math.floor(v / 0x10000) + a[3]*m) % 0x10000;
  r[4] = (v = Math.floor(v / 0x10000) + a[4]*m) % 0x10000;
  r[5] = (v = Math.floor(v / 0x10000) + a[5]*m) % 0x10000;
  r[6] = (v = Math.floor(v / 0x10000) + a[6]*m) % 0x10000;
  r[7] = (v = Math.floor(v / 0x10000) + a[7]*m) % 0x10000;
  r[8] = (v = Math.floor(v / 0x10000) + a[8]*m) % 0x10000;
  r[9] = (v = Math.floor(v / 0x10000) + a[9]*m) % 0x10000;
  r[10] = (v = Math.floor(v / 0x10000) + a[10]*m) % 0x10000;
  r[11] = (v = Math.floor(v / 0x10000) + a[11]*m) % 0x10000;
  r[12] = (v = Math.floor(v / 0x10000) + a[12]*m) % 0x10000;
  r[13] = (v = Math.floor(v / 0x10000) + a[13]*m) % 0x10000;
  r[14] = (v = Math.floor(v / 0x10000) + a[14]*m) % 0x10000;
  r[15] = Math.floor(v / 0x10000) + a[15]*m;
  curve25519_reduce(r);
  return r;
}

curve25519_x_to_y2 = function(x) {
	var val1 = curve25519_sqrmodp(x);
	var val2 = curve25519_mulasmall(x, 486662);
	val1 = curve25519_addmodp(val1, val2);
	val1 = curve25519_addmodp(val1, curve25519_one());
	val2 = curve25519_mulmodp(val1, x);
	return val2;
}

curve25519_dbl = function(x, z) {
  var x_2, z_2, m, n, o;
  m = curve25519_sqrmodp(curve25519_addmodp(x, z));
  n = curve25519_sqrmodp(curve25519_submodp(x, z));
  o = curve25519_submodp(m, n);
  x_2 = curve25519_mulmodp(n, m);
  z_2 = curve25519_mulmodp(curve25519_addmodp(curve25519_mulasmall(o, 121665), m), o);
  return [x_2, z_2];
}

curve25519_sum = function(x, z, x_p, z_p, x_1) {
  var x_3, z_3, k, l, p, q;
  p = curve25519_mulmodp(curve25519_submodp(x, z), curve25519_addmodp(x_p, z_p));
  q = curve25519_mulmodp(curve25519_addmodp(x, z), curve25519_submodp(x_p, z_p));
  x_3 = curve25519_sqrmodp(curve25519_addmodp(p, q));
  z_3 = curve25519_mulmodp(curve25519_sqrmodp(curve25519_submodp(p, q)), x_1);
  return [x_3, z_3];
}

curve25519_prep = function(a, b) {
	var x_1,x_2;
	x_1 = curve25519_addmodp(a,b);
	x_2 = curve25519_submodp(a,b);
	return [x_1,x_2];
}

curve25519_dbl2 = function(t1, t2) {
  var x_2, z_2, m, n, o;
  m = curve25519_sqrmodp(t1);
  n = curve25519_sqrmodp(t2);
  o = curve25519_submodp(m, n);
  x_2 = curve25519_mulmodp(n, m);
  z_2 = curve25519_mulmodp(curve25519_addmodp(curve25519_mulasmall(o, 121665), m), o);
  return [x_2, z_2];
}

function curve25519_sum2(t1, t2, t3, t4, x_1) {
  var x_3, z_3, p, q, r1, r2;
  p = curve25519_mulmodp(t2, t3);
  q = curve25519_mulmodp(t1, t4);
  r1 = curve25519_addmodp(p, q);
  r2 = curve25519_submodp(p, q);
  x_3 = curve25519_sqrmodp(r1);
  p = curve25519_sqrmodp(r2);
  z_3 = curve25519_mulmodp(p, x_1);
  return [x_3, z_3];
}

function curve25519(f, c, s) {
  var a, x_1, q;
  var num486671 = [27919,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
  var num39420360 = [33224,601,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
  var ss = new Int8Array(32);

  x_1 = c;
  q = [ curve25519_one(), curve25519_zero() ];
  a = [ x_1, curve25519_one() ];

  var n = 255;

  while (n >= 0) 
  {
    var nn, n_a;
    var b = curve25519_getbit(f, n);
    if (b == 0) 
    {
       n_a = curve25519_sum(a[0], a[1], q[0], q[1], x_1);
       nn = curve25519_dbl(q[0], q[1]);
    } 
    else 
    {
       nn = curve25519_sum(a[0], a[1], q[0], q[1], x_1);
       n_a = curve25519_dbl(a[0], a[1]);
    }
    q = nn; a = n_a;
    n--;
  }
  

  q[1] = curve25519_invmodp(q[1]);
  q[0] = curve25519_mulmodp(q[0], q[1]);
  curve25519_reduce(q[0]);
  if (s != null)
  {
	  var t = curve25519_cpy16(q[0]);
	  var t1 = curve25519_x_to_y2(t);
	  var t3 = curve25519_invmodp(a[1]);
	  var t2 = curve25519_mulmodp(a[0], t3);
	  t2 = curve25519_addmodp(t2, t);
	  t2 = curve25519_addmodp(t2, num486671);
	  t = curve25519_submodp(t, curve25519_nine());
	  t = curve25519_subtract(t, curve25519_nine());
	  t3 = curve25519_sqrmodp(t);
	  t = curve25519_mulmodp(t2, t3);
	  t = curve25519_submodp(t, t1);
	  t = curve25519_subtract(t, num39420360);
	  t1 = curve25519_mulmodp(t, curve25519_r2y())
	  kk = curve25519_convertToByteArray(f);
	  if (curve25519_isNegative(t1)!=0)
	  {
		  ss = curve25519_cpy32(kk);
	  }
	  else
	  {
		  curve25519_mula_small(ss, curve25519_order_times_8, 0, kk, 32, -1);
	  }
	  
	  var temp1 = new Int8Array(32);
	  var temp2 = new Int8Array(64);
	  var temp3 = new Int8Array(64);
	  temp1 = curve25519_cpy32(curve25519_order);
	  temp1 = curve25519_egcd32(temp2, temp3, ss, temp1);
	  ss = curve25519_cpy32(temp1);
	  if ((ss[31] & 0x80)!=0)
	  {
		  curve25519_mula_small(ss, ss, 0, curve25519_order, 32, 1);
	  }
	  var sss = curve25519_convertToShortArray(ss);
	  curve25519_fillShortArray(sss, s);
  }

  return q[0];
}

curve25519_keygen = function(s, curve) {
	curve25519_clamp(curve);
	return curve25519(curve, curve25519_nine(), s);
}

curve25519_sign = function(v, h, x, s) {
	tmp1=new Int8Array(65);
	tmp2=new Int8Array(33);
	for (i = 0; i < 32; i++)
	{
		v[i] = 0;
	}
	i = curve25519_mula_small(v, x, 0, h, 32, -1);
	zz = parseInt((15-v[31])/16);
	curve25519_mula_small(v, v, 0, curve25519_order, 32, parseInt((15-v[31])/16));
	curve25519_mula32(tmp1, v, s, 32, 1);
	curve25519_divmod(tmp2, tmp1, 64, curve25519_order, 32);
	w=0;
	for (k = 0; k < 32; k++)
	{
		v[k] = tmp1[k];
		w |= v[k];
	}
	return w != 0;
}

curve25519_verify = function(Y, v, h, P) {
	d=new Int8Array(32);
	var num486671 = [27919,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    var num39420360 = [33224,601,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	yx=new Array(3);
	yz=new Array(3);
	var s=new Array(2);
	var q=new Array(2);
	var t1=new Array(3);
	var t2=new Array(3);
	var vi = 0, hi = 0, di = 0, nvh=0, i=0, j=0, k=0, counter=1;

	var p = [ curve25519_nine(), curve25519_convertToShortArray(P) ];
	t2[0] = curve25519_x_to_y2(p[1]);
	t1[0] = curve25519_sqrtmodp(t2[0]);
	j = curve25519_isNegative(t1[0]);
	t2[0] = curve25519_addmodp(t2[0], num39420360);
	t2[1] = curve25519_mulmodp(curve25519_2y(), t1[0]);
	t1[j] = curve25519_subtract(t2[0], t2[1]);
	t1[1-j] = curve25519_add(t2[0], t2[1]);
	t2[0] = curve25519_cpy16(p[1]);
	t2[0] = curve25519_subtract(t2[0], curve25519_nine());
	t2[1] = curve25519_sqrmodp(t2[0]);
	t2[0] = curve25519_invmodp(t2[1]);
	s[0] = curve25519_mulmodp(t1[0], t2[0]);
	s[0] = curve25519_submodp(s[0], p[1]);
	s[0] = curve25519_submodp(s[0], num486671);
	s[1] = curve25519_mulmodp(t1[1], t2[0]);
	s[1] = curve25519_submodp(s[1], p[1]);
	s[1] = curve25519_submodp(s[1], num486671);
	
	for (i = 0; i < 32; i++) 
	{
		vi = (vi >> 8) ^ (v[i] & 0xFF) ^ ((v[i] & 0xFF) << 1);
		hi = (hi >> 8) ^ (h[i] & 0xFF) ^ ((h[i] & 0xFF) << 1);
		nvh = ~(vi ^ hi);
		di = (nvh & (di & 0x80) >> 7) ^ vi;
		di ^= nvh & (di & 0x01) << 1;
		di ^= nvh & (di & 0x02) << 1;
		di ^= nvh & (di & 0x04) << 1;
		di ^= nvh & (di & 0x08) << 1;
		di ^= nvh & (di & 0x10) << 1;
		di ^= nvh & (di & 0x20) << 1;
		di ^= nvh & (di & 0x40) << 1;
		d[i] = (di & 0xFF);
	}

	di = ((nvh & (di & 0x80) << 1) ^ vi) >> 8;

	yx[0] = curve25519_cpy16(curve25519_one());
	yx[1] = curve25519_cpy16(p[di]);
	yx[2] = curve25519_cpy16(s[0]);
	yz[0] = curve25519_cpy16(curve25519_zero());
	yz[1] = curve25519_cpy16(curve25519_one());
	yz[2] = curve25519_cpy16(curve25519_one());
	
	vi = 0;
	hi = 0;

	for (i = 32; i-- != 0; i=i) 
	{
		vi = (vi << 8) | (v[i] & 0xFF);
		hi = (hi << 8) | (h[i] & 0xFF);
		di = (di << 8) | (d[i] & 0xFF);

		for (j = 8; j-- !=0 ; j=j) 
		{
			k = ((vi ^ vi >> 1) >> j & 1) + ((hi ^ hi >> 1) >> j & 1);
			q = curve25519_prep(yx[0], yz[0]);
			t1[0] = curve25519_cpy16(q[0]);
			t2[0] = curve25519_cpy16(q[1]);
			q = curve25519_prep(yx[1], yz[1]);
			t1[1] = curve25519_cpy16(q[0]);
			t2[1] = curve25519_cpy16(q[1]);
			q = curve25519_prep(yx[2], yz[2]);
			t1[2] = curve25519_cpy16(q[0]);
			t2[2] = curve25519_cpy16(q[1]);
			
			q = curve25519_dbl2(t1[k], t2[k]);
			yx[0] = curve25519_cpy16(q[0]);
			yz[0] = curve25519_cpy16(q[1]);
			k = (di >> j & 2) ^ ((di >> j & 1) << 1);
			q = curve25519_sum2(t1[1], t2[1], t1[k], t2[k], p[di >> j & 1]);
			yx[1] = curve25519_cpy16(q[0]);
			yz[1] = curve25519_cpy16(q[1]);

			q = curve25519_sum2(t1[2], t2[2], t1[0], t2[0], s[((vi ^ hi) >> j & 2) >> 1]);
			yx[2] = curve25519_cpy16(q[0]);
			yz[2] = curve25519_cpy16(q[1]);
			curve25519_reduce(yx[0]);
			curve25519_reduce(yx[1]);
			curve25519_reduce(yx[2]);
			curve25519_reduce(yz[0]);
			curve25519_reduce(yz[1]);
			curve25519_reduce(yz[2]);
		}
	}

	k = (vi & 1) + (hi & 1);
	t1[0] = curve25519_invmodp(yz[k]);
	t1[1] = curve25519_mulmodp(yx[k], t1[0]);
	var YY = curve25519_convertToByteArray(t1[1]);
	curve25519_fillByteArray(YY, Y);
}

/** Helpers **/
hexchars = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

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

function hexstring_to_byteArray(str) 
{
    var len = str.length/2;
    var res = new Array(len);
    for(var i = 0; i < len; i++)
    {
        res[i] = parseInt("0x" + str.charAt(2*i) + str.charAt(2*i+1));
    }
    return res;
}

function shortArray_to_hex_string(ary) 
{
    var res = "";
    for(var i = 0; i < ary.length; i++)
    {
        res += hexchars[(ary[i] >> 4) & 0x0f] + hexchars[ary[i] & 0x0f] + hexchars[(ary[i] >> 12) & 0x0f] + hexchars[(ary[i] >> 8) & 0x0f];
    }
    return res;
}

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

function fromInt8Array(array)
{
	var val;
	result = new Array(array.length);
	for (i=0; i<array.length; i++)
	{
		if (array[i] < 0)
		{
			result[i] = (array[i] + 256);
		}
		else
		{
			result[i] = array[i];
		}
	}
	
	return result;
}

function arraysEqual(a, b) 
{
  	if (a == null || b == null)
  	{
  		return false;
  	}
  	if (a.length != b.length)
  	{
  		return false;
  	}
	for (var i = 0; i < a.length; ++i) 
  	{
  		if (a[i] != b[i])
  		{
  			return false;
  		}
  	}
  	return true;
}


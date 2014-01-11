// Copyright (c) 2007 Michele Bini
// Konstantin Welke, 2008:
// - moved into .js file, renamed all c255lname to curve25519_name
// - added curve25519_clamp()
// - functions to read from/to 8bit string
// - removed base32/hex functions (cleanup)
// - removed setbit function (cleanup, had a bug anyway)
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */
//
// The original curve25519 library was released into the public domain
// by Daniel J. Bernstein

// For testing
var numMula_small = 0;

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
  
curve25519_from8bitString = function(/*8bit string */ s) {
  var curve = curve25519_zero();
  if (32 != s.length)
    throw "curve25519_fromString(): input string must exactly be 32 bytes";
  for(var i = 0; i < 16; ++i)
    //weird encoding from curve25519lib...
    curve[i] = s.charCodeAt(31-i*2) | (s.charCodeAt(30-i*2) << 8);
  return curve;
}

curve25519_to8bitString = function(curve) {
  var s = "";
  //weird encoding from curve25519lib...
  //todo: check if this encoding also applies for DJB's code (probably doesnt? does he even handle encodings?)
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


/********************* Helpers *********************/
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

curve25519_log16 = function(text, a) {
	var b = shortArray_to_hex_string(a);
	addText(text + b);
}

curve25519_log32 = function(text, a) {
	var b = byteArray_to_hex_string(a);
	addText(text + b);
}

/********************* radix 2^8 math *********************/

curve25519_cpy32 = function(a) {
	var b = new Int8Array(32);
	for (i = 0; i < 32; i++)
	{
		b[i] = a[i];
	}
	return b;
}

/* p[m..n+m-1] = q[m..n+m-1] + z * x */
/* n is the size of x */
/* n+m is the size of p and q */
curve25519_mula_small = function(p, q, m, x, n, z) {
	numMula_small += 1;
	v=0;
	for (j=0; j<n; ++j) 
	{
		v += (q[j+m] & 0xFF) + z * (x[j] & 0xFF);
		p[j+m] = (v & 0xFF);
		v >>= 8;
	}
	return v;		
}

/* p += x * y * z  where z is a small integer
 * x is size 32, y is size t, p is size 32+t
 * y is allowed to overlap with p+32 if you don't care about the upper half  */
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

/* divide r (size n) by d (size t), returning quotient q and remainder r
 * quotient is size n-t+1, remainder is size t
 * requires t > 0 && d[t-1] != 0
 * requires that r[-1] and d[-1] are valid memory locations
 * q may overlap with r+t */
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

/* Returns x if a contains the gcd, y if b.
 * Also, the returned buffer contains the inverse of a mod b,
 * as 32-byte signed.
 * x and y must have 64 bytes space for temporary use.
 * requires that a[-1] and b[-1] are valid memory locations  */
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

/********************* radix 2^16 math *********************/
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

curve25519_substract = function (a, b) {
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
    //if (i > 240) { tracev("invmodp a", a); }
    a = curve25519_mulmodp(a, c);
    //if (i > 240) { tracev("invmodp a 2", a); }
  }
  a = curve25519_sqrmodp(a);
  a = curve25519_sqrmodp(a); a = curve25519_mulmodp(a, c);
  a = curve25519_sqrmodp(a);
  a = curve25519_sqrmodp(a); a = curve25519_mulmodp(a, c);
  a = curve25519_sqrmodp(a); a = curve25519_mulmodp(a, c);
  return a;
}

curve25519_sqrtmodp = function(x) {
	
	var t1 = curve25519_addmodp(x,x);
	var v = curve25519_invmodp(t1);
	var t2 = curve25519_sqrmodp(v);
	t2 = curve25519_mulmodp(t1, t2);
	t2 = curve25519_subtract(curve25519_one());
	t1 = curve25519_mulmodp(v, t2);
	t2 = curve25519_mulmodp(x, t1);
	return t2;
}

curve25519_mulasmall = function(a, m) {
  //var m = 121665;
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

/* Y^2 = X^3 + 486662 X^2 + X
 * t is a temporary  */
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

function curve25519_sum(x, z, x_p, z_p, x_1) {
  var x_3, z_3, k, l, p, q;
  p = curve25519_mulmodp(curve25519_submodp(x, z), curve25519_addmodp(x_p, z_p));
  q = curve25519_mulmodp(curve25519_addmodp(x, z), curve25519_submodp(x_p, z_p));
  x_3 = curve25519_sqrmodp(curve25519_addmodp(p, q));
  z_3 = curve25519_mulmodp(curve25519_sqrmodp(curve25519_submodp(p, q)), x_1);
  return [x_3, z_3];
}


function curve25519(f, c, s) {
  var a, x_1, q;
  var num486671 = [27919,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
  var num39420360 = [33224,601,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

  x_1 = c;
  q = [ curve25519_one(), curve25519_zero() ];
  a = [ x_1, curve25519_one() ];

  var n = 255;

  while (n >= 0) 
  {
    var nn, n_a;
    var b = curve25519_getbit(f, n);
    //addText("Bit " + n + "=" + b);
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
	  curve25519_log16("1) t=", t)
	  var t1 = curve25519_x_to_y2(t);
	  curve25519_log16("2) t1=", t1)
	  var t3 = curve25519_invmodp(a[1]);
	  curve25519_log16("3) t3=", t3)
	  var t2 = curve25519_mulmodp(a[0], t3);
	  curve25519_log16("4) t2=", t2)
	  t2 = curve25519_addmodp(t2, t);
	  curve25519_log16("5) t2=", t2)
	  t2 = curve25519_addmodp(t2, num486671);
	  curve25519_log16("6) t2=", t2)
	  //t = curve25519_submodp(t, curve25519_nine());
	  t = curve25519_substract(t, curve25519_nine());
	  curve25519_log16("7) t=", t)
	  t3 = curve25519_sqrmodp(t);
	  curve25519_log16("8) t3=", t3)
	  t = curve25519_mulmodp(t2, t3);
	  curve25519_log16("9) t=", t)
	  t = curve25519_submodp(t, t1);
	  curve25519_log16("10) t=", t)
	  t = curve25519_substract(t, num39420360);
	  curve25519_log16("11) t=", t)
	  t1 = curve25519_mulmodp(t, curve25519_r2y())
	  curve25519_log16("12) t1=", t1)
	
	  var ss = new Int8Array(32);
	  kk = curve25519_convertToByteArray(f);
	  curve25519_mula_small(ss, curve25519_order_times_8, 0, kk, 32, -1);
	  curve25519_log32("13) ss=", ss)
	  
	  // take reciprocal of s mod q
	  var temp1 = new Int8Array(32);
	  var temp2 = new Int8Array(64);
	  var temp3 = new Int8Array(64);
	  temp1 = curve25519_cpy32(curve25519_order);
	  curve25519_log32("14) temp1=", temp1)
	  temp1 = curve25519_egcd32(temp2, temp3, ss, temp1);
	  curve25519_log32("15) temp1=", temp1)
	  ss = curve25519_cpy32(temp1);
	  curve25519_log32("16) ss=", ss)
	  if ((ss[31] & 0x80)!=0)
	  {
		  curve25519_mula_small(ss, ss, 0, curve25519_order, 32, 1);
		  curve25519_log32("17) ss=", ss)
	  }
	  var sss = curve25519_convertToShortArray(ss);
	  curve25519_log16("18) sss=", sss)
	  curve25519_fillShortArray(sss, s);
	  curve25519_log16("19) s=", s)
  }

  return q[0];
}

curve25519_keygen = function(s, curve) {
	curve25519_clamp(curve);
	return curve25519(curve, curve25519_nine(), s);
}

/********* DIGITAL SIGNATURES *********/

/* Signature generation primitive, calculates (x-h)s mod q
 *   v  [out] signature value
 *   h  [in]  signature hash (of message, signature pub key, and context data)
 *   x  [in]  signature private key
 *   s  [in]  private key for signing
 * returns true on success, false on failure (use different x or h)
 */
curve25519_sign = function(v, h, x, s) {
	tmp1=new Int8Array(65);
	tmp2=new Int8Array(33);
	for (i = 0; i < 32; i++)
	{
		v[i] = 0;
	}
	i = curve25519_mula_small(v, x, 0, h, 32, -1);
	curve25519_log32("1) v=", v)
	zz = parseInt((15-v[31])/16);
	curve25519_mula_small(v, v, 0, curve25519_order, 32, parseInt((15-v[31])/16));
	curve25519_log32("2) v=", v)
	curve25519_mula32(tmp1, v, s, 32, 1);
	curve25519_log32("3) tmp1=", tmp1)
	curve25519_divmod(tmp2, tmp1, 64, curve25519_order, 32);
	curve25519_log32("4) tmp1=", tmp1)
	w=0;
	for (k = 0; k < 32; k++)
	{
		v[k] = tmp1[k];
		w |= v[k];
	}
	return w != 0;
}

/* Signature verification primitive, calculates Y = vP + hG
 *   Y  [out] signature public key
 *   v  [in]  signature value
 *   h  [in]  signature hash
 *   P  [in]  public key
 */
function verify2(Y, v, h, P) 
{
	// Y = v abs(P) + h G 
	/*d=new Int8Array(32);
    p=new Array(2); p[0] = new Long10(0,0,0,0,0,0,0,0,0,0); p[1] = new Long10(0,0,0,0,0,0,0,0,0,0);
    s=new Array(2); s[0] = new Long10(0,0,0,0,0,0,0,0,0,0); s[1] = new Long10(0,0,0,0,0,0,0,0,0,0);
	yx=new Array(3); yx[0] = new Long10(0,0,0,0,0,0,0,0,0,0); yx[1] = new Long10(0,0,0,0,0,0,0,0,0,0); yx[2] = new Long10(0,0,0,0,0,0,0,0,0,0);
	yz=new Array(3); yz[0] = new Long10(0,0,0,0,0,0,0,0,0,0); yz[1] = new Long10(0,0,0,0,0,0,0,0,0,0); yz[2] = new Long10(0,0,0,0,0,0,0,0,0,0);

    var num39420360 = [33224,601,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	var t1=new Array(3);
	var t2=new Array(3);
	var vi = 0, hi = 0, di = 0, nvh=0, i=0, j=0, k=0;

	// set p[0] to G and p[1] to P 
	var p = [ curve25519_nine(), curve25519_convertToShortArray(p)];

	// set s[0] to P+G and s[1] to P-G

	// s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662
	// s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662

	t2[0] = curve25519_x_to_y2(p[1]);
	t1[0] = curve25519_sqrtmodp(t2[0]);
	j = curve25519_isNegative(t1[0]);
	t2[0] = curve25519_addmodp(t2[0], num39420360);
	t2[1] = curve25519_mulmodp(curve25519_2y(), t1[0]);
	t1[j] = curve25519_submodp(t2[0], t2[1]);
	t1[1-j] = curve25519_addmodp(t2[0], t2[1]);
	t2[0] = curve25519_cpy16(p[1]);
	
	x_to_y2(t1[0], t2[0], p[1]);	// t2[0] = Py^2
	sqrt(t1[0], t2[0]);	// t1[0] = Py or -Py
	j = is_negative(t1[0]);		//      ... check which
	t2[0]._0 = t2[0]._0.add(getLong(39420360));		// t2[0] = Py^2 + Gy^2
	mul(t2[1], BASE_2Y, t1[0]);// t2[1] = 2 Py Gy or -2 Py Gy 
	sub(t1[j], t2[0], t2[1]);	// t1[0] = Py^2 + Gy^2 - 2 Py Gy 
	add(t1[1-j], t2[0], t2[1]);// t1[1] = Py^2 + Gy^2 + 2 Py Gy

	cpy(t2[0], p[1]);		// t2[0] = Px
	t2[0]._0 = t2[0]._0.subtract(getLong(9));			// t2[0] = Px - Gx
	sqr(t2[1], t2[0]);		// t2[1] = (Px - Gx)^2
	recip(t2[0], t2[1], 0);	// t2[0] = 1/(Px - Gx)^2
	mul(s[0], t1[0], t2[0]);	// s[0] = t1[0]/(Px - Gx)^2
	sub(s[0], s[0], p[1]);	// s[0] = t1[0]/(Px - Gx)^2 - Px
	s[0]._0 = s[0]._0.subtract(getLong(9 + 486662));		// s[0] = X(P+G)
	mul(s[1], t1[1], t2[0]);	// s[1] = t1[1]/(Px - Gx)^2
	sub(s[1], s[1], p[1]);	// s[1] = t1[1]/(Px - Gx)^2 - Px
	s[1]._0 = s[1]._0.subtract(getLong(9 + 486662));		// s[1] = X(P-G)
	mul_small(s[0], s[0], goog.math.Long.ONE);	// reduce s[0]
	mul_small(s[1], s[1], goog.math.Long.ONE);	// reduce s[1]


	// prepare the chain
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

	// initialize state
	set(yx[0], getLong(1));
	cpy(yx[1], p[di]);
	cpy(yx[2], s[0]);
	set(yz[0], getLong(0));
	set(yz[1], getLong(1));
	set(yz[2], getLong(1));

	// y[0] is (even)P + (even)G
	// y[1] is (even)P + (odd)G  if current d-bit is 0
	// y[1] is (odd)P + (even)G  if current d-bit is 1
	// y[2] is (odd)P + (odd)G
	
	vi = 0;
	hi = 0;

	// and go for it!
	for (i = 32; i-- != 0; i=i) 
	{
		vi = (vi << 8) | (v[i] & 0xFF);
		hi = (hi << 8) | (h[i] & 0xFF);
		di = (di << 8) | (d[i] & 0xFF);

		for (j = 8; j-- !=0 ; j=j) 
		{
			mont_prep(t1[0], t2[0], yx[0], yz[0]);
			mont_prep(t1[1], t2[1], yx[1], yz[1]);
			mont_prep(t1[2], t2[2], yx[2], yz[2]);

			k = ((vi ^ vi >> 1) >> j & 1) + ((hi ^ hi >> 1) >> j & 1);
			mont_dbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0]);

			k = (di >> j & 2) ^ ((di >> j & 1) << 1);
			mont_add(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1], p[di >> j & 1]);

			mont_add(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2], s[((vi ^ hi) >> j & 2) >> 1]);
		}
	}

	k = (vi & 1) + (hi & 1);
	recip(t1[0], yz[k], 0);
	mul(t1[1], yx[k], t1[0]);

	pack(t1[1], Y);*/
}
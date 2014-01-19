function addText(myText) 
{
  document.write("<h1>" + myText + "</h1>");
}

function test()
{
	//secretMessage = "Hello World!";
	//s2 = "secretPhrase";
	//secretMessage = "patriots";
	//s2 = "three";
	var secretMessage = "This is a secret message that needs to be signed";
	var s2 = "This is my very secret phrase";
	var signatureString;
	var success;
	var secretMsg = byteArray_to_hex_string(string_to_byteArray(secretMessage));
	var secretPhrase = byteArray_to_hex_string(string_to_byteArray(s2));
	var publicKey = getPublicKey(secretPhrase);
	addText("message: " + secretMessage);
	addText("secret phrase: " + s2);
	addText("public key: " + publicKey);

	addText("Signing... ");
	var signature = sign(secretMsg, secretPhrase);
	addText("Signature: " + signature);
	
	addText("Verifying... ");
	success = verify(signature, secretMsg, publicKey);
	addText("verify returned: " + success);

	var loop = 30;
	var time1=0, time2=0;
	var currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		publicKey = getPublicKey(secretPhrase);
	}
	var currentTimeMillisEnd = new Date().getTime();
	addText("Javascript needs " + ((currentTimeMillisEnd - currentTimeMillisBegin)/loop).toString() + "ms/getPublicKey");

	var currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		signature = sign(secretMsg, secretPhrase);
	}
	var currentTimeMillisEnd = new Date().getTime();
	time1 = ((currentTimeMillisEnd - currentTimeMillisBegin)/loop);
	addText("Javascript needs " + time1.toString() + "ms/sign");

	currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		success = verify(signature, secretMsg, publicKey);
	}
	currentTimeMillisEnd = new Date().getTime();
	time2 = ((currentTimeMillisEnd - currentTimeMillisBegin)/loop);
	addText("Javascript needs " + time2.toString() + "ms/verify");
	addText("sign + verify: " + (time1+time2).toString() + "ms");

	return;
}


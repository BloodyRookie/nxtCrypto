function addText(myText) 
{
  document.write("<h1>" + myText + "</h1>");
}

function test()
{
	addText("Test");
	countCalls = 1;
	secretMessage = "This is a secret message that needs to be signed";
	s2 = "This is my very secret phrase";
	publicKeyString = getPublicKey(s2);
	addText("message: " + secretMessage);
	addText("secret phrase: " + s2);
	addText("public key: " + publicKeyString);
	var secretMsg = byteArray_to_hex_string(string_to_byteArray(secretMessage));

	addText("Signing... ");
	signatureString = sign(string_to_byteArray(secretMessage), s2);
	addText("Signature: " + signatureString);
	
	addText("Verifying... ");
	success = verify(signatureString, secretMsg, publicKeyString);
	addText("verify returned: " + success);

	countCalls = 0;
	addText("Speed test");
	var loop = 10;
	var currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		publicKeyString = getPublicKey(s2);
	}
	var currentTimeMillisEnd = new Date().getTime();
	addText("Javascript needs " + ((currentTimeMillisEnd - currentTimeMillisBegin)/loop).toString() + "ms/getPublicKey");

	var currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		signature = sign(string_to_byteArray(secretMessage), s2);
	}
	var currentTimeMillisEnd = new Date().getTime();
	addText("Javascript needs " + ((currentTimeMillisEnd - currentTimeMillisBegin)/loop).toString() + "ms/sign");

	currentTimeMillisBegin = new Date().getTime();
	for (u=0; u<loop; u++)
	{
		success = verify(signatureString, secretMsg, publicKeyString);
	}
	currentTimeMillisEnd = new Date().getTime();
	addText("Javascript needs " + ((currentTimeMillisEnd - currentTimeMillisBegin)/loop).toString() + "ms/verify");
	addText("Finished");

	return;
}


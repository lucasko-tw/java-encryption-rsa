### Asymmetric Encryption in JAVA :
There is a sample code that is modified by other github codes.

### Save keys into file.
``` JAVA

	writePemFile(priv, "RSA PRIVATE KEY", fnPrivateKey );
	writePemFile(pub, "RSA PUBLIC KEY",  fnPublicKey );
``` 

### Get keys from file.
``` JAVA

	private static PrivateKey getPrivateKeyFromFile(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}

	private static PublicKey getPublicKeyFromFile(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}
```

### Encryption and Decryption
``` JAVA
		
		Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER);
		byte[] input = "Hello World!!".getBytes();

		// ENCRYPT
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(cipherText));

		// DECRYPT
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(cipherText);
		System.out.println("plain : " + new String(plainText));
```

### Output

	cipher: i�};6L�Xf�xnl/����Y(�
	�^/nvVS�5�	'��eR-ye�7Zmq��l�����ӆm��v��$׀���|�����4�AW'|뇜D䣡�ΙFu!		�E���'YrڝG��$��R�|��O�
	plain : Hello World!!

 

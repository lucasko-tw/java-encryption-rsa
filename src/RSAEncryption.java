import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAEncryption {

	protected final static Logger LOGGER = Logger.getLogger(RSAEncryption.class.toString());
	public static final int KEY_SIZE = 1024;
	private static String ALGORITHM = "RSA";
	private static String PROVIDER = "BC";

	public static void main(String[] args)
			throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		LOGGER.info("Provider.");

		KeyPair keyPair = generateRSAKeyPair();
		RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

		String fnPrivateKey = "rsa.pri" ;
		String fnPublicKey = "rsa.pub" ;
		
		// save key
		writePemFile(priv, "RSA PRIVATE KEY", fnPrivateKey );
		writePemFile(pub, "RSA PUBLIC KEY",  fnPublicKey );

		// load key
		KeyFactory factory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
		PrivateKey privKey = null;
		PublicKey pubKey = null;

		try {
			privKey = getPrivateKeyFromFile(factory,  fnPrivateKey );
			LOGGER.info(String.format("Instantiated private key: %s", privKey));
			pubKey = getPublicKeyFromFile(factory,  fnPublicKey );
			LOGGER.info(String.format("Instantiated public key: %s", pubKey));
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

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

	}

	private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
		generator.initialize(KEY_SIZE);

		KeyPair keyPair = generator.generateKeyPair();
		LOGGER.info("RSA key pair generated.");
		return keyPair;
	}

	private static void writePemFile(Key key, String description, String filename)
			throws FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(key, description);
		pemFile.write(filename);
		LOGGER.info(String.format("%s successfully writen in file %s.", description, filename));
	}

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
}
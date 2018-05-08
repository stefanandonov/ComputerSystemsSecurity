package STSProtocolInPractice;


import javax.security.*;

import lab1.ByteConverter;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import javax.crypto.*;

public class CertificateAuthority {
	
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private MessageDigest digest;
	private Map<String,PublicKey> registered;
	
	public CertificateAuthority () throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = kpg.generateKeyPair();
		publicKey=pair.getPublic();
		privateKey=pair.getPrivate();
		digest = MessageDigest.getInstance("SHA-256");
		registered = new HashMap<>();
		
		System.out.println("A CertificateAuthority has been created with private key: \n"
				+ ByteConverter.byteArrayToHex(privateKey.getEncoded()) + 
				"\nand public key: \n"
				+ ByteConverter.byteArrayToHex(publicKey.getEncoded()) + "\n");
	}
	
	public void registerUser(User u) {
		registered.put(u.getName(), u.getPublicKey());
		
		System.out.println("User "+u.getName()+" with public key:\n" 
		+ ByteConverter.byteArrayToHex(u.getPublicKey().getEncoded()) + "\nhas been registered into the CA\n");
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public Certificate sign (CertificateRequest cr) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		
		if (!registered.containsKey(cr.getName()) 
				|| !check(registered.get(cr.getName()).getEncoded(),cr.getPublicKey()))
		return null;
		
		byte [] nameBytes = cr.getName().getBytes();		
		byte [] alphaBytes = ByteBuffer.allocate(8).putLong(cr.getAlpha().longValue()).array();	
		byte [] pBytes = ByteBuffer.allocate(8).putLong(cr.getP().longValue()).array();		
		byte [] bytesForSignature = new byte [nameBytes.length+alphaBytes.length+pBytes.length+cr.getPublicKey().length];
		
		System.arraycopy(nameBytes, 0, bytesForSignature, 0, nameBytes.length);
		System.arraycopy(cr.getPublicKey(), 0, bytesForSignature, nameBytes.length, cr.getPublicKey().length);
		System.arraycopy(alphaBytes, 0, bytesForSignature, nameBytes.length+cr.getPublicKey().length, alphaBytes.length);
		System.arraycopy(pBytes, 0, bytesForSignature, nameBytes.length+cr.getPublicKey().length+alphaBytes.length, pBytes.length);
		//System.out.println("Bytes for signature: \n"+ByteConverter.byteArrayToHex(bytesForSignature));
		byte [] hashed = this.digest.digest(bytesForSignature);
		
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, this.privateKey);
		
		byte [] signedBytes = c.doFinal(hashed);
		
		System.out.println("\n The CA signs "+cr.getName()+" certificate\n");
		
		return new Certificate(cr.getName(), cr.getPublicKey(), cr.getAlpha().longValue(), cr.getP().longValue(), signedBytes);
	}
	
	public boolean check (byte [] encoded, byte [] publicKeyBytes){
		return Arrays.equals(encoded, publicKeyBytes);
	}
	

}

package lab1;

import java.math.BigInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
	
	private byte [] key;
	
	public Encryptor(byte [] key) {
		this.key=key;
	}
	
	public byte[] encrypt (byte [] plainText) throws Exception{
		SecretKeySpec sks = new SecretKeySpec(key,"AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, sks);
		
		
		return cipher.doFinal(plainText);
		
	}
	
	public byte[] decrypt(byte [] cipherText) throws Exception{
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sks);

        return cipher.doFinal(cipherText);
	}
	
	public static void main (String [] args){
		
	}

	

}

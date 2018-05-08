package STSProtocolInPractice;
import lab1.ByteConverter;

import javax.security.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class User {
	
	private String name;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private MessageDigest digest;
	
	private BigInteger DHprivate;
	private BigInteger DHpublic;
	
	private BigInteger alpha;
	private BigInteger p;
	
	private Key sharedKey;
	
	private BigInteger otherPersonDHValue;
	
	public User (String name) throws NoSuchAlgorithmException{
		this.name=name;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = kpg.generateKeyPair();
		publicKey=pair.getPublic();
		privateKey=pair.getPrivate();
		digest = MessageDigest.getInstance("SHA-256");
	}

	public final void setDHprivate(long dHprivate) {
		DHprivate = BigInteger.valueOf(dHprivate);
	}

	public final void setDHpublic(BigInteger alpha, BigInteger p) {
		DHpublic = alpha.modPow(DHprivate, p);
	}

	public final void setSharedKey(Key sharedKey) {
		this.sharedKey = sharedKey;
	}
	
	public FirstMessage generateFirstMessage(long alpha, long p){
		Random random = new Random();
		setDHprivate(random.nextLong());
		setDHpublic(BigInteger.valueOf(alpha),BigInteger.valueOf(p));
		this.alpha=BigInteger.valueOf(alpha);
		this.p=BigInteger.valueOf(p);
		System.out.println(this.name + " sends the FIRST MESSAGE with the content: ");
		return new FirstMessage(this.alpha.longValue(),this.p.longValue(),this.DHpublic.longValue());
	}
	
	public SecondMessage recieveFirstMessage(FirstMessage fm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		this.alpha=fm.getAlpha();
		this.p=fm.getP();
		Random random = new Random();
		setDHprivate(random.nextLong());
		setDHpublic(alpha,p);
		this.otherPersonDHValue=fm.getDHpublic();
		
		System.out.println(this.name+" recieves the FIRST MESSAGE and generates his public DH parameter: "+this.DHpublic);
		
		
		byte [] ayax = new byte [16];
		System.arraycopy(ByteBuffer.allocate(8).putLong(this.DHpublic.longValue()).array(), 0, ayax, 0, 8);
		System.arraycopy(ByteBuffer.allocate(8).putLong(fm.getDHpublic().longValue()).array(), 0, ayax, 8, 8);
		
		
		byte [] hashed = digest.digest(ayax);
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, this.privateKey);
		
		byte [] signedBytes = c.doFinal(hashed);
		
		BigInteger calculatedValue= fm.getDHpublic().modPow(this.DHprivate, this.p);
		byte[] commonKeyBytes=ByteBuffer.allocate(8).putLong(calculatedValue.longValue()).array();
		byte[] finalBytes=new byte[16];
		System.arraycopy(commonKeyBytes, 0, finalBytes, 0, 8);
		for(int i=8;i<16;i++)finalBytes[i]=0;
		
		//encryption with shared calculated key
		Cipher c1 = Cipher.getInstance("AES");
		Key key=new SecretKeySpec(finalBytes, "AES");
		c1.init(Cipher.ENCRYPT_MODE, key);
		byte[] finalEncrypted=c1.doFinal(signedBytes);
		
		setSharedKey(key);
		
		System.out.println(this.name+" generates the common key: "+ByteConverter.byteArrayToHex(this.sharedKey.getEncoded()));
		
		System.out.println(this.name + " sends his public DH parameter and the encrypted version of a^y and a^x"
				+ "\nPublic DH parameter: " + this.DHpublic + "\nencrypted data: " + 
				ByteConverter.byteArrayToHex(finalEncrypted));
		return new SecondMessage(this.DHpublic.longValue(),finalEncrypted);
		
	}
	
	public CertificateRequest sendCertificateRequest()
	{
		return new CertificateRequest(this.alpha.longValue(),this.p.longValue(),this.getPublicKeyBytes(),this.name);
	}
	
	public boolean validateCertificate(Certificate certificate, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		//decrypting with CA's public key
		Cipher c=Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decrypted=c.doFinal(certificate.getSignedBytes());
		
		
		//testing
		certificate.changeName("Oscar");
		byte[] alphaBytes=ByteBuffer.allocate(8).putLong(certificate.getAlpha().longValue()).array();
		byte[] pBytes=ByteBuffer.allocate(8).putLong(certificate.getP().longValue()).array();
		byte[] nameBytes=certificate.getName().getBytes();
		byte[] concatenated=new byte[nameBytes.length+certificate.getPublicKey().length+alphaBytes.length+pBytes.length];
		System.arraycopy(nameBytes, 0, concatenated, 0, nameBytes.length);
		System.arraycopy(certificate.getPublicKey(), 0, concatenated, nameBytes.length, certificate.getPublicKey().length);
		System.arraycopy(alphaBytes, 0, concatenated, nameBytes.length+certificate.getPublicKey().length, alphaBytes.length);
		System.arraycopy(pBytes, 0, concatenated, nameBytes.length+certificate.getPublicKey().length+alphaBytes.length, pBytes.length);
		//System.out.println("Bytes for verification: \n"+ByteConverter.byteArrayToHex(concatenated));
		byte[] hashed=this.digest.digest(concatenated);
		
		//System.out.println(ByteConverter.byteArrayToHex(hashed));
		//System.out.println(ByteConverter.byteArrayToHex(decrypted));
		boolean result=Arrays.equals(hashed, decrypted);
		if(!result)
		{
			System.out.println("\nCertificate not validated by "+this.getName()+"!\n");
			return false;
		}
		else
		{
			System.out.println("\nCertificate validated by "+this.getName()+"!\n");
			return true;
		}
	}
	
	public ThirdMessage validateSecondMessage (SecondMessage sm, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		//decrypting using shared key
		//long calculatedValue=((long) Math.pow(aPackage.getPublicDhParameter(),this.privateDhParameter))%this.p;
		BigInteger cValue = sm.getDHpublic().modPow(this.DHprivate, this.p);
		long calculatedValue = cValue.longValue();
		byte[] commonKeyBytes=ByteBuffer.allocate(8).putLong(calculatedValue).array();
		byte[] finalBytes=new byte[16];
		System.arraycopy(commonKeyBytes, 0, finalBytes, 0, 8);
		for(int i=8;i<16;i++)finalBytes[i]=0;
		
		Cipher c = Cipher.getInstance("AES");
		Key sharedKey=new SecretKeySpec(finalBytes, "AES");
		
		c.init(Cipher.DECRYPT_MODE, sharedKey);
		byte[] decrypted=c.doFinal(sm.getEncryptedBytes());
		//checking other's signature
		Cipher c1 = Cipher.getInstance("RSA");
		c1.init(Cipher.DECRYPT_MODE, key);
		byte[] finalDecrypted=c1.doFinal(decrypted);
		
		byte[] concatenated=new byte[16];
		System.arraycopy(ByteBuffer.allocate(8).putLong(sm.getDHpublic().longValue()).array(), 0, concatenated, 0, 8);
		System.arraycopy(ByteBuffer.allocate(8).putLong(this.DHpublic.longValue()).array(), 0, concatenated, 8, 8);
		byte[] hashed=this.digest.digest(concatenated);
		
		boolean result=Arrays.equals(finalDecrypted,hashed);
		if(!result)
		{
			System.out.println("\nSecond message not validated by "+this.getName()+"!\n");
			return null;
		}
		
		System.out.println("\nSecond message validated by "+this.getName()+"!\n");
		//System.out.println(this.name+" has the shared key!");
		
		byte[] resultConcatenated=new byte[16];
		System.arraycopy(ByteBuffer.allocate(8).putLong(this.DHpublic.longValue()).array(), 0, resultConcatenated, 0, 8);
		System.arraycopy(ByteBuffer.allocate(8).putLong(sm.getDHpublic().longValue()).array(), 0, resultConcatenated, 8, 8);
		byte[] resultHashed=this.digest.digest(resultConcatenated);
		
		//signing 
		Cipher c2 = Cipher.getInstance("RSA");
		c2.init(Cipher.ENCRYPT_MODE, this.privateKey);
		byte[] encryptedOnce=c2.doFinal(resultHashed);
		
		//encrypting with shared key
		Cipher c3 = Cipher.getInstance("AES");
		c3.init(Cipher.ENCRYPT_MODE, sharedKey);
		byte[] finalEncrypted=c3.doFinal(encryptedOnce);
		
		setSharedKey(sharedKey);
		
		return new ThirdMessage(finalEncrypted);
	}
	
	public boolean validateThirdMessage (ThirdMessage tm, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		//decrypting with shared key
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, this.sharedKey);
		byte[] decryptedOnce=c.doFinal(tm.getEncryptedBytes());
		
		//checking other's signature
		Cipher c1 = Cipher.getInstance("RSA");
		c1.init(Cipher.DECRYPT_MODE, key);
		byte[] hashedDecrypted=c1.doFinal(decryptedOnce);
		
		byte[] resultConcatenated=new byte[16];
		System.arraycopy(ByteBuffer.allocate(8).putLong(this.otherPersonDHValue.longValue()).array(), 0, resultConcatenated, 0, 8);
		System.arraycopy(ByteBuffer.allocate(8).putLong(this.DHpublic.longValue()).array(), 0, resultConcatenated, 8, 8);
		byte[] resultHashed=this.digest.digest(resultConcatenated);
		
		boolean result=Arrays.equals(hashedDecrypted,resultHashed);
		if(!result)
		{
			System.out.println("Final step validation FAILED!\n");
			return false;
		}
		else
		{
			System.out.println("\nFinal step validation is SUCCESSFUL!\n");
			return true;
		}
	}

	private byte [] getPublicKeyBytes() {
		// TODO Auto-generated method stub
		return this.publicKey.getEncoded();
	}

	public String getName() {
		return this.name;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public Key getSharedKey () {
		return this.sharedKey;
	}
	
	
	
	
	

}

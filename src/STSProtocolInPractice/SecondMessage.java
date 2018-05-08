package STSProtocolInPractice;

import java.math.BigInteger;

public class SecondMessage {
	
	private BigInteger DHpublic;
	private Certificate certificate;
	private byte [] encryptedBytes;
	
	public SecondMessage(long dHpublic, byte[] encryptedBytes) {
		super();
		DHpublic = BigInteger.valueOf(dHpublic);
		//this.certificate = certificate;
		this.encryptedBytes = encryptedBytes;
	}

	public Certificate getCertificate() {
		return certificate;
	}
	
	/*public setCertificate (Certificate c){
		this.certificate=c;
	}*/

	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	public BigInteger getDHpublic() {
		return DHpublic;
	}

	public byte[] getEncryptedBytes() {
		return encryptedBytes;
	}
	
	/*public String toString() {
		return String.format("Bob sends his certificate ", args)
	}*/
	
	

}

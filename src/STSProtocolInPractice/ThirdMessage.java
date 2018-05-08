package STSProtocolInPractice;

public class ThirdMessage {
	
	private Certificate certificate;
	private byte [] encryptedBytes;
	
	public ThirdMessage(byte[] encryptedBytes) {
		super();
		//this.certificate = certificate;
		this.encryptedBytes = encryptedBytes;
	}

	public Certificate getCertificate() {
		return certificate;
	}
	
	public void setCertificate (Certificate c) {
		certificate=c;
	}

	public byte[] getEncryptedBytes() {
		return encryptedBytes;
	}
	
	

}

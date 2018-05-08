package STSProtocolInPractice;

import java.math.BigInteger;

public class Certificate {
	
	private String name;
	private byte [] publicKey;
	private BigInteger alpha;
	private BigInteger p;
	private byte [] signedBytes;
	
	
	public Certificate(String name, byte[] publicKey, long alpha, long p, byte[] signedBytes) {
		super();
		this.name = name;
		this.publicKey = publicKey;
		this.alpha = BigInteger.valueOf(alpha);
		this.p = BigInteger.valueOf(p);
		this.signedBytes = signedBytes;
	}


	public String getName() {
		return name;
	}


	public byte[] getPublicKey() {
		return publicKey;
	}


	public BigInteger getAlpha() {
		return alpha;
	}


	public BigInteger getP() {
		return p;
	}


	public byte[] getSignedBytes() {
		return signedBytes;
	}


	public void changeName(String string) {
		this.name=string;
		
	}

}

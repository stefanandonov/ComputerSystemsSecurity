package STSProtocolInPractice;

import java.math.BigInteger;

public class CertificateRequest {
	
	private BigInteger alpha;
	private BigInteger p;
	private byte [] publicKey;
	private String name;
	
	public CertificateRequest(long alpha, long p, byte[] publicKey, String name) {
		super();
		this.alpha = BigInteger.valueOf(alpha);
		this.p = BigInteger.valueOf(p);
		this.publicKey = publicKey;
		this.name = name;
	}

	public BigInteger getAlpha() {
		return alpha;
	}

	public BigInteger getP() {
		return p;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public String getName() {
		return name;
	}
	
	

}

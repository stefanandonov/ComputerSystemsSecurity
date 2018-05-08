package STSProtocolInPractice;

import java.math.BigInteger;

public class FirstMessage {
	private BigInteger alpha;
	private BigInteger p;
	private BigInteger DHpublic;
	
	public FirstMessage (long alpha, long p, long DHpublic){
		this.alpha=BigInteger.valueOf(alpha);
		this.p=BigInteger.valueOf(p);
		this.DHpublic=BigInteger.valueOf(DHpublic);	
		
		System.out.println(String.format(
				"Alpha == %d \n"
				+ "P == %d \n"
				+ "DH Public for Alice == %d", this.alpha.longValue(),this.p.longValue(),this.DHpublic.longValue()) + "\n");
	}

	public BigInteger getAlpha() {
		return alpha;
	}

	public BigInteger getP() {
		return p;
	}

	public BigInteger getDHpublic() {
		return DHpublic;
	}
	
	

}

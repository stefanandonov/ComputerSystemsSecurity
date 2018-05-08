package STSProtocolInPractice;

import lab1.ByteConverter;

public class Test {

	public static void main(String[] args) throws Exception {
		
		CertificateAuthority CA = new CertificateAuthority();
		
		User Alice = new User("Alice");
		User Bob = new User("Bob");
		
		CA.registerUser(Alice);
		CA.registerUser(Bob);
		
		SecondMessage sm = Bob.recieveFirstMessage(Alice.generateFirstMessage(5, 23));
		sm.setCertificate(CA.sign(Bob.sendCertificateRequest()));
		
		if (sm.getCertificate()!= null){
			if (Alice.validateCertificate(sm.getCertificate(), CA.getPublicKey())){
				ThirdMessage tm = Alice.validateSecondMessage(sm, Bob.getPublicKey());
				tm.setCertificate(CA.sign(Alice.sendCertificateRequest()));
				if (tm.getCertificate()!=null){					
					if (Bob.validateCertificate(tm.getCertificate(), CA.getPublicKey())){
						Bob.validateThirdMessage(tm, Alice.getPublicKey());
					}
				}
					
				
			}
			else {
				System.out.println("FAILED");
			}
		}
		
		

	}

}

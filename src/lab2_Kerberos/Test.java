package lab2_Kerberos;
import lab1.ByteConverter;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Test {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		/*SecureRandom sr = new SecureRandom();
		byte bytes [] = new byte[16];
		sr.nextBytes(bytes);
		System.out.println(ByteConverter.byteArrayToHex(bytes));
		
		Date d = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("ddMMYY  hh:mm:ss");
		System.out.println(sdf.format(d).getBytes().length);*/
		byte [] idAlice = {1};
		byte [] aliceKey = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		User Alice = new User(UserType.SENDER,ByteConverter.byteArrayWithLength(idAlice, 16),aliceKey);
		
		byte [] idBob = {2};
		byte [] bobKey = {10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10};
		User Bob = new User(UserType.RECIEVER,ByteConverter.byteArrayWithLength(idBob, 16),bobKey);
		
		List<byte []> AliceRQST = Alice.sendRequest(ByteConverter.byteArrayWithLength(idBob, 16));
		
		KDC kcd = new KDC(aliceKey,bobKey);
		
		kcd.recieveRequest(AliceRQST);
		
		Alice.recieveYaYb(kcd.sendYaYb());
		
		Bob.recieveYabYb(Alice.sendYabYb());
		
		
		//Testing the encryption and decryption after establishing the session key		
		String message = "Test primerFINKI";		
		System.out.println(ByteConverter.byteArrayToHex(message.getBytes()));		
		byte [] encrypted = Alice.encryptMessage(message.getBytes());		
		System.out.println(ByteConverter.byteArrayToHex(encrypted));
		byte [] decrypted = Bob.decryptMessage(encrypted);
		System.out.println(ByteConverter.byteArrayToHex(decrypted));
		System.out.println(Arrays.equals(message.getBytes(), decrypted));
		
		
		
	}

}

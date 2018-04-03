package lab1;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class WPA2Test {
	
	public static void main (String [] args) throws Exception{
		byte [] preamble = "PREAMBLE".getBytes();
		byte [] sourceMAC = {12,13,14,15,16,17};
		byte [] destinationMAC = {12,10,9,7,25,26};
		byte [] qos = {12};
		byte [] pn = {0,0,0,0,0,10};
		Header header = new Header (preamble,sourceMAC,destinationMAC,qos,pn);
		
		//Pecatenje na informacii za header-ot
		System.out.println(header.toString());
		
		String d = "Ova e porakata koja sto se sodrzi vo paketot i potrebno e da se prati od "
				+ "sourceMAC adresata do destinationMAC adresata..asd ";
		Data data = new Data(d);
		
		//Generiranje i pecatenje na NONCE od header-ot
		byte [] nonce = header.generateNonce();		
		System.out.println(ByteConverter.byteArrayToHex(nonce));
		
		//Kreiranje na ramkata
		Frame f = new Frame(header,data);
		System.out.println(f.toHexString());
		
		byte [] key = {12,13,14,15,20,20,21,22,23,120,12,13,99,89,87,67};
		
		byte [] MIC = null;
		try {
			MIC = f.calculateMIC(key);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("MIC: "+ ByteConverter.byteArrayToHex(MIC));
		
		
		//Test slucaevi za enkripcija i dekripcija vo Counter mode
		System.out.println("ORIGINAL:");
		data.getBlocks().stream().forEach(block -> System.out.print(ByteConverter.byteArrayToHex(block)));
		System.out.println();
		
		System.out.println("ENCRYPTED");
		List<byte []> encryptedData = f.encryptData(key);
		encryptedData.stream().forEach(array -> {
			System.out.print(ByteConverter.byteArrayToHex(array));
		});
		
		byte [] destinationMAC1 = {10,101,1,1,1,1};
		header = new Header (preamble,sourceMAC,destinationMAC1,qos,pn);
		f = new Frame(header,data);
		
		
		System.out.println();
		System.out.println("DECRYPTED");
		List<byte []> decryptedData = f.decryptData(key, encryptedData);
		decryptedData.stream().forEach(array -> {
			System.out.print(ByteConverter.byteArrayToHex(array));
		});
		
		System.out.println();
		System.out.println(f.verifyMIC(key, decryptedData,MIC));
		
		
	}

}

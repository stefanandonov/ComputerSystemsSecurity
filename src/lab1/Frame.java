package lab1;
import java.util.*;
import java.util.stream.IntStream;
import java.security.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;

public class Frame {
	Header header;
	Data data;
	BigInteger counter;
	
	public Frame(Header header, Data data) {
		this.header=header;
		this.data=data;		
		counter = BigInteger.valueOf(0);
	}
	
	public Header getHeader() {
		return header;
	}
	
	public void setHeader(Header h) {
		header=header;
	}
	
	public static byte [] xor (byte [] array1, byte [] array2) {
		byte [] result = new byte [array1.length];
		
		//System.out.println(ByteConverter.byteArrayToHex(array1));
		//System.out.println(ByteConverter.byteArrayToHex(array2));
		
		IntStream.range(0, array1.length).forEach(i -> {
			result[i] = (byte) (array1[i] ^ array2[i]);
		});
		
		return result;
		
	}
	
	public byte [] calculateMIC(byte [] key) throws Exception {
		byte [] nonce = header.generateNonce();
		Encryptor e = new Encryptor(key);
		
		byte [] x1 = e.encrypt(nonce);		
		
		for (int i=0;i<header.getBlocks().size();i++){
			
			x1=xor(x1,header.getBlocks().get(i));
			x1=e.encrypt(x1);
		}
		
		for (int i=0;i<data.getBlocks().size();i++){
			x1=xor(x1,data.getBlocks().get(i));
			x1=e.encrypt(x1);
		}
		
		byte [] MIC1 = new byte [8];
		
		for (int i=0;i<8;i++)
			MIC1[i]=x1[i];
		
		MIC1 = xor(e.encrypt(nonce),ByteConverter.byteArrayWithLength(MIC1, 16));
	
		return MIC1;
	}
	
	public byte [] calculateMICwithDecryptedData (byte [] key, List<byte []> decryptedData) throws Exception{
		byte [] nonce = header.generateNonce();
		Encryptor e = new Encryptor(key);
		
		byte [] x1 = e.encrypt(nonce);		
		
		for (int i=0;i<header.getBlocks().size();i++){
			
			x1=xor(x1,header.getBlocks().get(i));
			x1=e.decrypt(x1);
		}
		
		for (int i=0;i<decryptedData.size();i++){
			x1=xor(x1,decryptedData.get(i));
			x1=e.encrypt(x1);
		}
		
		byte [] MIC1 = new byte [8];
		
		for (int i=0;i<8;i++)
			MIC1[i]=x1[i];
		
		MIC1 = xor(e.encrypt(nonce),ByteConverter.byteArrayWithLength(MIC1, 16));
	
		return MIC1;
	}
	
	public List<byte []> encryptData(byte [] key){
		byte [] nonce = header.generateNonce();
		counter = BigInteger.valueOf(1);
		List <byte []> result = new ArrayList<>();
		Encryptor e = new Encryptor(key);
		
		//byte [] x1 = xor(nonce,counter.toByteArray());
		data.getBlocks().forEach(block -> { 
			try {
				result.add(xor(block,e.encrypt(xor(nonce,ByteConverter.byteArrayWithLength(counter.toByteArray(), 16)))));
				counter = counter.add(BigInteger.valueOf(1));
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		});
		
		return result;
	}
	
	public List<byte []> decryptData(byte [] key, List<byte []> input) {
		byte [] nonce = header.generateNonce();
		counter = BigInteger.valueOf(1);
		List <byte []> result = new ArrayList<>();
		Encryptor e = new Encryptor(key);
		
		input.forEach(block -> {
			try {
				result.add(xor(block,e.encrypt(xor(nonce,ByteConverter.byteArrayWithLength(counter.toByteArray(), 16)))));
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			counter = counter.add(BigInteger.valueOf(1));
		});
		
		return result;
	}
	
	public boolean verifyMIC (byte [] key, List<byte []> decryptedData, byte [] MIC) throws Exception {
		//System.out.println(ByteConverter.byteArrayToHex(this.calculateMIC(key)));
		//System.out.println(ByteConverter.byteArrayToHex(this.calculateMICwithDecryptedData(key, decryptedData)));
		
		byte [] MICoriginal = MIC;
		byte [] MICafterDecryption = this.calculateMICwithDecryptedData(key, decryptedData);

		for (int i=0;i<MICoriginal.length;i++)
			if (MICoriginal[i]!=MICafterDecryption[i])
				return false;
		
		return true;
	}
	
	public String toString() {
		return header.toString() + "\n" + "DATA:\n"+data.toString();
	}
	
	public String toHexString() {
		return header.toHexString() + "\n" + data.toHexString();
	}

}

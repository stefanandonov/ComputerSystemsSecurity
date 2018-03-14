package lab1;
import java.math.BigInteger;
public class ByteConverter {
	
	public static byte [] byteArrayWithLength(byte [] array, int l){
		/*
		 * Converts a byte array into a bigger byte array with length l with zeros left padding
		 */
		byte [] newArray = new byte [l];
		
		for (int i=0;i<l-array.length;i++)
			newArray[i]=(byte) 0;
		
		int j=0;
		for (int i=l-array.length;i<l;i++)
			newArray[i]=array[j++];
		
		return newArray;
	}
	
	public static String byteArrayToHex(byte [] input){
		StringBuilder sb = new StringBuilder();
		
		for (int i=0;i<input.length;i++){
			sb.append(String.format("%02X", input[i]));
		}
		
		return sb.toString();
	}
	
	public static byte [] hexToByteArray(String hexInput){
		BigInteger bi = new BigInteger(hexInput,16);
		return bi.toByteArray();
	}
	
}

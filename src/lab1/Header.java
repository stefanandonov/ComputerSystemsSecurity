package lab1;
import java.util.*;
import java.security.*;
import java.io.*;

/**
 * 
 * @author stefan5andonov
 *
 */

public class Header {
	
	private byte [] sourceMAC;
	private byte [] destinationMAC;
	private byte [] preamble;
	private byte [] qos;
	private byte [] pn;
	
	public Header() {
		sourceMAC = new byte[6];
		destinationMAC = new byte[6];
		preamble = new byte[8];
		pn = new byte[6];
		qos = new byte[1];
		
	}
	
	public Header (byte [] preamble, byte [] sourceMAC, byte [] destinationMAC, byte [] qos, byte [] pn){
		this.preamble=preamble;
		this.sourceMAC=sourceMAC;
		this.destinationMAC=destinationMAC;
		this.qos=qos;
		this.pn=pn;
	}
	
	public byte [] generateNonce() {
		byte [] nonce = new byte [16];
		
		for (int i=0;i<6;i++)
			nonce[i]=pn[i];
		int j=6;
		for (int i=0;i<6;i++){
			
			nonce[j]=sourceMAC[i];
			j++;
		}
		nonce[12]=qos[0];
		
		for (int i=13;i<16;i++)
			nonce[i]=(byte) 0;	
		
		return nonce;
	}
	
	public byte[] getBytes() {
		byte [] allBytes = new byte [21];
		int j=0;
		
		for (int i=0;i<8;i++){
			allBytes[j]=preamble[i];
			j++;
		}
		
		for (int i=0;i<6;i++){
			allBytes[j]=sourceMAC[i];
			j++;
		}
		
		for (int i=0;i<6;i++){
			allBytes[j]=destinationMAC[i];
			j++;
		}
		
		
		allBytes[j++]=qos[0];
		
	
		return allBytes;
		
		
	}
	
	public List<byte []> getBlocks() {
		List blocks = new ArrayList<>();		
		byte [] allBlocks = getBytes();		
		byte [] subList = new byte [16];
		int j = 0;
		for (int i=0;i<allBlocks.length;i++){
			
			if (j%16==0 && j!=0){
				blocks.add(subList);
				subList = new byte [16];
				j=0;
				subList[j]=allBlocks[i];
				j++;
			}
			else {
				subList[j]=allBlocks[i];
				j++;				
			}			
			if (i==allBlocks.length-1){
				int number = 16 - (i%16) - 1;
				
				while (number>0) {
					subList[j]= (byte) 0;
					j++;
					number--;
				}
				blocks.add(subList);
			}
		}		
		return blocks;
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append("Preamble: \n");
		sb.append(ByteConverter.byteArrayToHex(this.preamble)+"\n");
		
		sb.append("Source MAC address: \n").append(ByteConverter.byteArrayToHex(sourceMAC)+"\n");
		
		sb.append("Destination MAC address: \n").append(ByteConverter.byteArrayToHex(destinationMAC)+"\n");
		
		sb.append("QoS: \n").append(ByteConverter.byteArrayToHex(qos)+"\n");
		
		sb.append("PN: \n").append(ByteConverter.byteArrayToHex(pn)+"\n");
		
		return sb.toString();
	}
	
	public String toHexString() {
		return ByteConverter.byteArrayToHex(getBytes());
	}
}

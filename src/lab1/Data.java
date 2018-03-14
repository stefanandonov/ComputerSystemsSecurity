package lab1;
import java.util.*;

public class Data {
	
	private String data;
	
	public Data(String data){
		this.data=data;
	}
	
	public byte []  getBytes() {
		return data.getBytes();
	}
	
	public List<byte[]> getBlocks() {
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
		return data.toString();
	}
	
	public String toHexString() {
		return ByteConverter.byteArrayToHex(data.getBytes());
	}


}

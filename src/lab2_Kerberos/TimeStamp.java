package lab2_Kerberos;

import java.util.Date;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.*;

public class TimeStamp {
	
	private Date stamp;
	
	public TimeStamp() {
		stamp = new Date();
	}
	
	public TimeStamp(Date stamp){
		this.stamp=stamp;
	}
	
	public byte [] toBytes() {		
		return this.getStamp().getBytes();
	}
	
	public String getStamp() {
		SimpleDateFormat sdf = new SimpleDateFormat("ddMMyy  HH:mm:ss");
		return sdf.format(stamp);
	}
	
	public static TimeStamp getStamp (byte [] bytes) throws ParseException{
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes)
			sb.append((char) b);
		
		SimpleDateFormat sdf = new SimpleDateFormat("ddMMyy  HH:mm:ss");
		
		return new TimeStamp(sdf.parse(sb.toString()));
	}
	
	public static boolean verifyTimeStamp (byte [] timestamp, byte [] lifetime) throws ParseException{
		TimeStamp now = new TimeStamp();
		
		TimeStamp old = getStamp(timestamp);
		
		BigInteger lt = new BigInteger(lifetime);
		long diff = (now.stamp.getTime()-old.stamp.getTime())/1000;
		
		return diff < lt.longValue();
	}
	
	
}

package lab2_Kerberos;
import java.text.ParseException;
import java.util.*;

public interface Contactable {
	
	UserType getType();
	
	byte [] getID();
	
	void setID(byte [] id);
	
	void setPrivateKey(byte [] key);
	
	byte [] getPrivateKey();
	
	byte [] generateNonceR();
	
	List<byte []> sendRequest(byte [] recieverID);
	
	void recieveYaYb(List<List<byte []>> YaYb) throws Exception;
	
	boolean verifyNonceR(byte [] nonceR);
	
	boolean verifyOtherPersonId(byte [] id);
	
	boolean verifyLifetime();
	
	byte [] generateTimestamp();
	
	List<List<byte []>> sendYabYb() throws Exception;
	
	void recieveYabYb(List<List<byte []>> YabYb) throws Exception;
	
	boolean verifyTimestamp() throws ParseException;
	
	void setSessionKey(byte [] sessionKey);
	
	byte [] encryptMessage(byte [] message) throws Exception;
	
	byte [] decryptMessage(byte [] message) throws Exception;

}

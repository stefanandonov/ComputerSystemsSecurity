package lab2_Kerberos;
import lab1.ByteConverter;
import lab1.Encryptor;
import java.security.*;
import java.text.ParseException;

import javax.crypto.*;
import java.util.*;

public class User implements Contactable {
	
	private byte [] privateKey;
	private byte [] id;	
	private UserType type;
	
	private byte [] nonceR;
	private byte [] sessionKey;
	private byte [] lifetime;
	private byte [] timeStamp;
	private boolean verification;
	private byte [] otherPersonId;
	private List<byte []> Yb;
	private List<byte []> Yab;
	
	
	public User (UserType type, byte [] id, byte [] privateKey){
		this.type=type;		
		this.privateKey=privateKey;
		this.id=id;
		nonceR = null;
		sessionKey=null;
		lifetime=null;
		timeStamp=null;	
		verification=false;
		otherPersonId=null;
		Yb = null;
		Yab = null;
		
		if (type==UserType.SENDER){
			nonceR=this.generateNonceR();
		}
	}

	@Override
	public UserType getType() {
		
		return this.type;
	}

	@Override
	public byte[] getID() {
		
		return this.id;
	}

	@Override
	public void setID(byte [] id) {
		this.id=id;
	}

	@Override
	public void setPrivateKey(byte[] key) {
		this.privateKey=key;

	}

	@Override
	public byte[] getPrivateKey() {
		return privateKey;
	}

	@Override
	public byte[] generateNonceR() {
		SecureRandom sr = new SecureRandom();
		byte bytes [] = new byte[16];
		sr.nextBytes(bytes);
		this.nonceR=bytes;
		return bytes;
	}

	@Override
	public List<byte[]> sendRequest(byte[] recieverID) {
		
		List<byte [] > request = null;
		
		if (type!=UserType.RECIEVER){
			request = new ArrayList<>();		
			request.add(this.id);
			request.add(recieverID);
			this.otherPersonId=recieverID;
			request.add(this.nonceR);
		}	
		System.out.println("===SENDING REQUEST TO KDC===");
		System.out.println("The sender with ID: \n"+ByteConverter.byteArrayToHex(this.id) +"\n"
				+ "is sending a request to KDC for establishing a session key with the reciever with ID:\n"+
				ByteConverter.byteArrayToHex(recieverID)+". \nThe generated Nonce for the sender is:\n"+
				ByteConverter.byteArrayToHex(this.nonceR));
		
		System.out.println();
		
		
		return request; 
	}

	@Override
	public void recieveYaYb(List<List<byte[]>> YaYb) throws Exception {
		if (type==UserType.RECIEVER)
			return;
		
		Encryptor e = new Encryptor(this.privateKey);
		
		List<byte []> Ya = YaYb.get(0);
		this.Yb = YaYb.get(1);
		
		byte [] kses = Ya.get(0);
		byte [] rNonce = Ya.get(1);
		byte [] lifeTime = Ya.get(2);
		byte [] idReciever = Ya.get(3);
		
		kses = e.decrypt(kses);
		this.sessionKey=kses;
		rNonce = e.decrypt(rNonce);
		lifeTime = e.decrypt(lifeTime);
		this.lifetime=lifeTime;
		idReciever = e.decrypt(idReciever);
	 
		
		if (verifyNonceR(rNonce) && verifyOtherPersonId(idReciever) && verifyLifetime())
			this.verification=true;
		else
			this.verification=false;
		
		System.out.println("===THE SENDER RECIEVES YA AND YB ENCRYPTED VALUES. HE/SHE DECRYPTS THEM AND VERIFIES \nTHE NONCE, THE LIFETIME AND THE RECIEVER ID===");
		System.out.println("RESULT FROM THE VERIFICATION: "+(verifyNonceR(rNonce) && verifyOtherPersonId(idReciever) && verifyLifetime())+"\n");
		//System.out.println(ByteConverter.byteArrayToHex(rNonce)+"\n"+ByteConverter.byteArrayToHex(this.nonceR));
		//System.out.println(verifyNonceR(rNonce)+" "+ verifyOtherPersonId(idReciever) + " " + verifyLifetime());
		
	}

	@Override
	public boolean verifyNonceR(byte [] nonce) {
		for (int i=0;i<nonce.length;i++)
			if (this.nonceR[i]!=nonce[i])
				return false;
		
		return true;
	}

	@Override
	public boolean verifyOtherPersonId(byte[] id) {
		for (int i=0;i<id.length;i++)
			if (this.otherPersonId[i]!=id[i])
				return false;
		
		return true;
	}

	@Override
	public boolean verifyLifetime() {
		for (byte b : lifetime)
			if ((int) b < 0)
				return false;
		return true;
	}

	@Override
	public byte[] generateTimestamp() {
		TimeStamp t = new TimeStamp();
		this.timeStamp=t.toBytes();
		return t.toBytes();
	}

	@Override
	public List<List<byte[]>> sendYabYb() throws Exception {
		
		
		if (type==UserType.RECIEVER)
			return null;
		List<List<byte []>> YabYb = new ArrayList<>();
		
		Encryptor e = new Encryptor(sessionKey);
		this.Yab = new ArrayList<>();
		Yab.add(e.encrypt(this.id));
		this.generateTimestamp();
		Yab.add(e.encrypt(this.timeStamp));
		
		YabYb.add(Yab);
		YabYb.add(Yb);
		
		return YabYb;
	}

	@Override
	public void recieveYabYb(List<List<byte[]>> YabYb) throws Exception {
		
		if (type==UserType.SENDER)
			return;
		
		List<byte []> Yabab = YabYb.get(0);
		List<byte []> Ybb = YabYb.get(1);
		
		Encryptor e = new Encryptor(this.privateKey);
		
		this.sessionKey = e.decrypt(Ybb.get(0));
		
		Encryptor e1 = new Encryptor(this.sessionKey);
		this.otherPersonId= e1.decrypt(Yabab.get(0));
		this.lifetime = e.decrypt(Ybb.get(2));
		this.timeStamp = e1.decrypt(Yabab.get(1));
		
		if (verifyOtherPersonId(otherPersonId) && this.verifyLifetime() && this.verifyTimestamp())
			this.verification=true;
		else
			this.verification=false;
		
		System.out.println("===THE RECIEVER RECIEVES YAB AND YB. \nHE/SHE VERIFIES THE SENDER'S ID, THE LIFETIME AND THE SENDER'S TIMESTAMP ===");
		//System.out.println(verifyOtherPersonId(otherPersonId) + " " + this.verifyLifetime() + " " + this.verifyTimestamp());
		System.out.println("RESULT FROM THE VERIFICATION: "+(verifyOtherPersonId(otherPersonId) && this.verifyLifetime() && this.verifyTimestamp())+"\n");

	}

	@Override
	public boolean verifyTimestamp() throws ParseException {
		TimeStamp t = TimeStamp.getStamp(this.timeStamp);
		
		return TimeStamp.verifyTimeStamp(this.timeStamp, this.lifetime);

	}

	@Override
	public void setSessionKey(byte[] sessionKey) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] encryptMessage(byte[] message) throws Exception {
		// TODO Auto-generated method stub
		Encryptor e = new Encryptor(this.sessionKey);
		return e.encrypt(message);
	}

	@Override
	public byte[] decryptMessage(byte[] message) throws Exception {
		Encryptor e = new Encryptor(this.sessionKey);
		return e.decrypt(message);
	}

}

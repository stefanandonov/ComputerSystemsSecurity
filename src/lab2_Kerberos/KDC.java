package lab2_Kerberos;
import lab1.ByteConverter;
import lab1.Encryptor;
import java.util.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;

public class KDC {
	
	private byte [] keySender;
	private byte [] keyReciever;
	private byte [] sessionKey;
	private byte [] IDa;
	private byte [] IDb;
	private byte [] nonceSender;
	private byte [] lifetime;
	
	
	public KDC(byte [] keySender, byte [] keyReciever) {
		this.keyReciever=keyReciever;
		this.keySender = keySender;
		sessionKey=null;
		this.IDa=null;
		this.IDb=null;
		this.nonceSender = null;
		lifetime = null;
		lifetime = this.generateLifetime();
		this.generateRandomSessionKey();
		
		System.out.println("===THE KDC IS INFORMED THAT THE SENDER WANTS TO COMMUNICATE WITH THE RECIEVER===");
		
	}
	public void generateRandomSessionKey(){
		
		SecureRandom sr = new SecureRandom();
		byte [] bytes = new byte [16];
		sr.nextBytes(bytes);
		this.sessionKey=bytes;
	}
	
	public byte [] generateLifetime() {
		
		Random rdm = new Random();
		int lifetime = rdm.nextInt(2);
		++lifetime;
		return ByteConverter.byteArrayWithLength(BigInteger.valueOf(lifetime).toByteArray(),16);
	}
	
	public void recieveRequest(List<byte []> rqst){
		IDa = rqst.get(0);
		IDb = rqst.get(1);
		this.nonceSender = rqst.get(2);
		
		System.out.println("===THE KDC RECIEVES THE REQUEST FROM THE SENDER===\n");
		/*System.out.println(ByteConverter.byteArrayToHex(IDa));
		System.out.println(ByteConverter.byteArrayToHex(IDb));
		System.out.println(ByteConverter.byteArrayToHex(nonceSender));*/
	
	}
	
	
	
	public List<byte []> generateYa() throws Exception{
		List<byte []> ya = new ArrayList<>();
		Encryptor e = new Encryptor(this.keySender);
		
		ya.add(e.encrypt(this.sessionKey));
		ya.add(e.encrypt(nonceSender));
		ya.add(e.encrypt(this.lifetime));
		ya.add(e.encrypt(this.IDb));
		
		System.out.println("===THE KDC GENERATES THE ENCRYPTED VALUES FOR Ya===");
		System.out.println("ENCRYPTED SESSION KEY: "+ByteConverter.byteArrayToHex(ya.get(0)));
		System.out.println("ENCRYPTED NONCE FROM THE SENDER: "+ByteConverter.byteArrayToHex(ya.get(1)));
		System.out.println("ENCRYPTED LIFETIME: "+ByteConverter.byteArrayToHex(ya.get(2)));
		System.out.println("ENCRYPTED ID OF THE RECIEVER: "+ByteConverter.byteArrayToHex(ya.get(3)));
		System.out.println();
		return ya;
	}
	
	public List<byte []> generateYb() throws Exception {
		List<byte []> yb = new ArrayList<>();
		Encryptor e = new Encryptor(this.keyReciever);
		
		yb.add(e.encrypt(this.sessionKey));
		yb.add(e.encrypt(this.IDa));
		yb.add(e.encrypt(this.lifetime));
		
		System.out.println("===THE KDC GENERATES THE ENCRYPTED VALUES FOR Yb===");
		System.out.println("ENCRYPTED SESSION KEY: "+ByteConverter.byteArrayToHex(yb.get(0)));
		System.out.println("ENCRYPTED ID OF THE SENDER: "+ByteConverter.byteArrayToHex(yb.get(1)));
		System.out.println("ENCRYPTED LIFETIME: "+ByteConverter.byteArrayToHex(yb.get(2)));
		System.out.println();
		
		return yb;
	}
	
	public List<List<byte []>> sendYaYb() throws Exception {
		
		List<List<byte []>> YaYb = new ArrayList<>();
		YaYb.add(this.generateYa());
		YaYb.add(this.generateYb());
		return YaYb;
	}
	
	
}

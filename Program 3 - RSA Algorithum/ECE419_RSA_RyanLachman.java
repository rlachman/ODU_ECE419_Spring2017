
import java.math.*; 
import java.util.*; 
import java.io.*;
 
public class Main{
	
	private BigInteger N;
	private BigInteger e;
 
	public Main(BigInteger e, BigInteger N) 
	{
		this.e = e;
		this.N = N;
	}
 
	public static void main (String[] args) throws Exception
	{
		BigInteger e = new BigInteger("6551");
		BigInteger N = new BigInteger("712446816787");
		
		Main rsa = new Main(e,N);  
		System.out.println("The message to be encrypted : oduisgreat");
		System.out.println("Value of n : 712446816787");
		System.out.println("Value of e : 6551");
 
		String message = "oduisgreat";
		System.out.println("String in Bytes: " + bytesToString(message.getBytes()));

		// Encrypt the string
		byte[] encrypted = rsa.encrypt(message.getBytes());
		System.out.println("Encrypted Message in string: " + bytesToString(encrypted));
	}
 
	//Get String from Bytes
	private static String bytesToString(byte[] encrypted)
	{ 
		String test = ""; 
		for (byte b : encrypted) 
		{
			test += Byte.toString(b);
		}
 
		return test;
	}
 
	//Encrypt message
	public byte[] encrypt(byte[] message) 
	{
		return (new BigInteger(message)).modPow(e, N).toByteArray();
	}
 
}
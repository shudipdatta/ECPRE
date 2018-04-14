import it.unisa.dia.gas.jpbc.Element;

public class Main {

	public static void main(String[] args) {
		
		ECPRE ecpre = new ECPRE();
		ecpre.Pairing();
		/*
		//create node 1
		Element[] keys1 = ecpre.GenerateKey();
		Element pvtKey1 = keys1[0];
		Element pubKey1 = keys1[1]; 
		Element invPvt1 = keys1[2];
		
		//create node 2
		Element[] keys2 = ecpre.GenerateKey();
		Element pvtKey2 = keys2[0];
		Element pubKey2 = keys2[1]; 
		Element invPvt2 = keys2[2];
		
		//create node 3
		Element[] keys3 = ecpre.GenerateKey();
		Element pvtKey3 = keys3[0];
		Element pubKey3 = keys3[1]; 
		Element invPvt3 = keys3[2];
		
		//create proxy keys
		Element proxyKey12 = ecpre.GenerateProxyKey(invPvt1, pubKey2);
		Element proxyKey13 = ecpre.GenerateProxyKey(invPvt1, pubKey3);
		Element proxyKey23 = ecpre.GenerateProxyKey(invPvt2, pubKey3);
		
		//String testString = "Hello, This will be a complicated test one time. "
		//		+ "Hello, This will be a complicated test two times. "
		//		+ "Hello, This will be a complicated test three times.";
		String testString = "Hello, This will be a complicated test one time. Hello,";
		
		//encryption & decryption [1->3]
		Element[] ciphers13 = ecpre.Encryption(testString.getBytes(), pubKey1, proxyKey13);
		Element reEnc13 = ciphers13[0];
		Element cipher13 = ciphers13[1];
		
		Element plainText13 = ecpre.Decryption(reEnc13, cipher13, invPvt3);
		System.out.println(new String(plainText13.toBytes()));
		System.out.println("Test");
		
		//encryption & decryption [1->2->3]
		Element[] ciphers12 = ecpre.Encryption("Hello, This will be a complicated test two times. Hello, This will be a complicated test two times.".getBytes(), pubKey1, proxyKey12);
		Element reEnc12 = ciphers12[0];
		Element cipher12 = ciphers12[1];
		
		Element[] ciphers23 = ecpre.ReEncryption(cipher12, pubKey2, proxyKey23);
		Element reEnc23 = ciphers23[0];
		Element cipher23 = ciphers23[1];
		
		Element plainText123 = ecpre.Decryption(reEnc23, cipher23, invPvt3);
		System.out.println(new String(plainText123.toBytes()));
		*/
		
		//create node 1
		byte[][] keys1 = ecpre.GenerateKey();
		byte[] pvtKey1 = keys1[0];
		byte[] pubKey1 = keys1[1]; 
		byte[] invPvt1 = keys1[2];
		
		//create node 2
		byte[][] keys2 = ecpre.GenerateKey();
		byte[] pvtKey2 = keys2[0];
		byte[] pubKey2 = keys2[1]; 
		byte[] invPvt2 = keys2[2];
		
		//create node 3
		byte[][] keys3 = ecpre.GenerateKey();
		byte[] pvtKey3 = keys3[0];
		byte[] pubKey3 = keys3[1]; 
		byte[] invPvt3 = keys3[2];
		
		//create proxy keys
		byte[] proxyKey12 = ecpre.GenerateProxyKey(invPvt1, pubKey2);
		byte[] proxyKey13 = ecpre.GenerateProxyKey(invPvt1, pubKey3);
		byte[] proxyKey23 = ecpre.GenerateProxyKey(invPvt2, pubKey3);
		
		
		//String testString = "Hello, This will be a complicated test one time. "
		//		+ "Hello, This will be a complicated test two times. "
		//		+ "Hello, This will be a complicated test three times.";
		
		String testString = "Hello, This will be a complicated test one time. Hello, This will not work";
		/*
		//encryption & decryption [1->3]
		byte[] reEnc13 = ecpre.ReEncryption(pubKey1, proxyKey13);
		byte[] cipher13 = ecpre.Encryption(testString.getBytes());
		
		byte[] plainText13 = ecpre.Decryption(reEnc13, cipher13, invPvt3);
		System.out.println(new String(plainText13));
		*/
		
		//encryption & decryption [1->2->3]
		byte[] reEnc12 = ecpre.ReEncryption(pubKey1, proxyKey12);
		byte[] cipher12 = ecpre.Encryption(testString.getBytes());
		
		byte[] reEnc23 = ecpre.ReEncryption(pubKey2, proxyKey23);
		//byte[] cipher23 = ecpre.Encryption(testString.getBytes());
		
		byte[] plainText123 = ecpre.Decryption(reEnc23, cipher12, invPvt3);
		System.out.println(new String(plainText123));
		
		//signature scheme
		byte[] signature1 = ecpre.SignMessage(cipher12, pvtKey1);
		System.out.println(ecpre.VerifySignature(cipher12, signature1, pubKey1));
	}
}

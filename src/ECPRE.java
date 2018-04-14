import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;


public class ECPRE {
	
	@SuppressWarnings("rawtypes")
	Field Zr, GT, C;
	//Zr -> [pvtKey, invPvtKey]
	//C -> [pubKey, proxyKey]
	//GT -> [reEnc]	
	Element G, K, Zk;
	Pairing pairing;

	int rBits = 160;
	int qBits = 512;
	int plainByteLen = qBits/8-4; //512/8=64;
	int cipherByteLen = qBits/8*2;
	
	
	@SuppressWarnings("rawtypes")
	public void Pairing() {
		// JPBC Type A pairing generator
		PairingParametersGenerator paramGenerator = new TypeACurveGenerator(rBits, qBits);
		PairingParameters params = paramGenerator.generate();
		pairing = PairingFactory.getPairing(params);
		//Bilinear Pairing
		Zr = pairing.getZr();
		GT = pairing.getGT();
		G = pairing.getG1().newRandomElement().getImmutable();
		K = Zr.newRandomElement().getImmutable();
		Zk = pairing.pairing(G, G.powZn(K)).getImmutable();
		C = G.getField();
	}
	
	/*
	public Element[] GenerateKey() {
		Element pvtKey = Zr.newRandomElement().getImmutable();
		Element pubKey = G.powZn(pvtKey).getImmutable();
		Element invPvt = pvtKey.invert();	
		Element[] keys = {pvtKey, pubKey, invPvt};
		return keys;
	}
	
	public Element GenerateProxyKey(Element invPvtA, Element pubKeyB) {
		Element proxyKeyAB = pubKeyB.powZn(invPvtA);
		return proxyKeyAB;
	}
	
	public Element[] Encryption(byte[] plainText, Element pubKeyA, Element proxyKeyAB) {
		Element E = GT.newRandomElement();
		E.setFromBytes(plainText);
		Element cipher = Zk.mul(E);
		return ReEncryption(cipher, pubKeyA, proxyKeyAB);
	}
	
	public Element[] ReEncryption(Element cipher, Element pubKeyA, Element proxyKeyAB) {
		Element reCipher = pubKeyA.powZn(K);
		Element reEncAB = pairing.pairing(reCipher, proxyKeyAB);
		Element[] ciphers = {reEncAB, cipher};
		return ciphers;
	}
	
	public Element Decryption(Element reEncAB, Element cipher, Element invPvtB) {
		Element reCipher = reEncAB.powZn(invPvtB);
		Element plainText = cipher.div(reCipher);
		return plainText;
	}
	*/
	
	public byte[][] GenerateKey() {
		Element pvtKey = Zr.newRandomElement().getImmutable();
		Element pubKey = G.powZn(pvtKey).getImmutable();
		Element invPvt = pvtKey.invert();	
		byte[][] keys = {pvtKey.toBytes(), pubKey.toBytes(), invPvt.toBytes()};
		return keys;
	}
	
	public byte[] GenerateProxyKey(byte[] invPvtA, byte[] pubKeyB) {
		Element elemInvPvtA = Zr.newElement();
		Element elemPubKeyB = C.newElement();
		elemInvPvtA.setFromBytes(invPvtA);
		elemPubKeyB.setFromBytes(pubKeyB);
		
		Element proxyKeyAB = elemPubKeyB.powZn(elemInvPvtA);
		return proxyKeyAB.toBytes();
	}
	
//	public byte[] Encryption(byte[] plainText) {
//		Element E = GT.newElement();
//		E.setFromBytes(plainText);
//		Element cipher = Zk.mul(E);
//		return cipher.toBytes();
//	}
	
//	public byte[] Encryption(byte[] plainText) {
//		byte[] bytePlainText = new byte[((int) Math.ceil(plainText.length/(double)plainByteLen)) * plainByteLen];
//		System.arraycopy(plainText, 0, bytePlainText, 0, plainText.length);
//		int blockNum = (int) Math.ceil(plainText.length/(double)plainByteLen);
//		byte[] byteCipher = new byte[blockNum*cipherByteLen];
//		
//		for(int i=0; i<blockNum; i++) {
//			Element E = GT.newElement();
//			byte[] plainBlock = new byte[plainByteLen];
//			System.arraycopy(bytePlainText, plainByteLen*i, plainBlock, 0, plainByteLen);
//			E.setFromBytes(plainBlock);
//			Element cipher = Zk.mul(E);
//			System.arraycopy(cipher.toBytes(), 0, byteCipher, cipherByteLen*i, cipherByteLen);
//		}
//		return byteCipher;
//	}
	
	public byte[] Encryption(byte[] plainText) {
		int blockNum = (int) Math.ceil(plainText.length/(double)plainByteLen);
		byte[] byteCipher = new byte[blockNum*cipherByteLen];
		
		for(int i=0; i<blockNum; i++) {
			Element E = GT.newElement();
			byte[] plainBlock = new byte[plainText.length - plainByteLen*i < plainByteLen? plainText.length - plainByteLen*i: plainByteLen];
			System.arraycopy(plainText, plainByteLen*i, plainBlock, 0, plainBlock.length);
			E.setFromBytes(plainBlock);
			Element cipher = Zk.mul(E);
			System.arraycopy(cipher.toBytes(), 0, byteCipher, cipherByteLen*i, cipherByteLen);
		}
		return byteCipher;
	}
	
	public byte[] ReEncryption(byte[] pubKeyA, byte[] proxyKeyAB) {
		Element elemPubKeyA = C.newElement();
		Element elemProxyKeyAB = C.newElement();
		elemPubKeyA.setFromBytes(pubKeyA);
		elemProxyKeyAB.setFromBytes(proxyKeyAB);
		
		Element reCipher = elemPubKeyA.powZn(K);
		Element reEncAB = pairing.pairing(reCipher, elemProxyKeyAB);
		return reEncAB.toBytes();
	}
	
	public byte[] Decryption(byte[] reEncAB, byte[] cipher, byte[] invPvtB) {
		Element elemReEncAB = GT.newElement();
		Element elemInvPvtB = Zr.newElement();
		elemReEncAB.setFromBytes(reEncAB);
		elemInvPvtB.setFromBytes(invPvtB);
		Element reCipher = elemReEncAB.powZn(elemInvPvtB);
		
		int blockNum = (int) Math.ceil(cipher.length/(double)cipherByteLen);
		byte[] bytePlain = new byte[blockNum*plainByteLen];
		for(int i=0; i<blockNum; i++) {
			byte[] cipherBlock = new byte[cipherByteLen];
			System.arraycopy(cipher, cipherByteLen*i, cipherBlock, 0, cipherByteLen);
			Element elemCipher = GT.newElement();
			elemCipher.setFromBytes(cipherBlock);			
			Element plainText = elemCipher.div(reCipher);
			
			byte[] bytePlainText = plainText.toBytes();
			int initIndex=0;
			while(bytePlainText[initIndex] == 0) initIndex++;			
			
			System.arraycopy(plainText.toBytes(), initIndex, bytePlain, plainByteLen*i, plainByteLen);
		}
		return bytePlain;
	}

//	public byte[] Decryption(byte[] reEncAB, byte[] cipher, byte[] invPvtB) {
//		Element elemReEncAB = GT.newElement();
//		Element elemCipher = GT.newElement();
//		Element elemInvPvtB = Zr.newElement();
//		elemReEncAB.setFromBytes(reEncAB);
//		elemCipher.setFromBytes(cipher);
//		elemInvPvtB.setFromBytes(invPvtB);
//		
//		Element reCipher = elemReEncAB.powZn(elemInvPvtB);
//		Element plainText = elemCipher.div(reCipher);
//		return plainText.toBytes();
//	}
	public byte[] Hash(byte[] value) throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			byte[] bytesOfMessage = value;
			final byte[] resultByte = messageDigest.digest(bytesOfMessage);
			//System.out.println("Hash Length: " + resultByte.length); 
			return resultByte;
		} 
	    catch (Exception ex) {
	        ex.printStackTrace();
	        System.out.println("Hash Exception:");
	    }

	    return null;
	}
	
	public byte[] SignMessage(byte[] cipher, byte[] pvtKey) {		
		try {
			byte[] hash = Hash(cipher);
			Element elemHash = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);
			
			Element elemPvtKey = Zr.newElement();
			elemPvtKey.setFromBytes(pvtKey);
			Element signature = elemHash.powZn(elemPvtKey);
			return signature.toBytes();
		} 
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return new byte[0];
		}
	}
	
	public boolean VerifySignature(byte[] cipher, byte[] signature, byte[] pubKey) {
		try {
			byte[] hash = Hash(cipher);
			Element elemHash = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);
			
			Element elemSig = C.newElement();
			Element elemPubKey = C.newElement();
			elemSig.setFromBytes(signature);
			elemPubKey.setFromBytes(pubKey);
			
			Element e1 = pairing.pairing(elemSig, G);
			Element e2 = pairing.pairing(elemHash, elemPubKey);
			
			return e1.isEqual(e2)? true: false;
		} 
		catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
			return false;
		}
	}
	
}
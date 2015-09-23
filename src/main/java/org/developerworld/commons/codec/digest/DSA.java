package org.developerworld.commons.codec.digest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.developerworld.commons.lang.StringUtils;


/**
 * @version 20090717
 * @author Roy.Huang
 * 
 */
public class DSA {

	public final static String ALGORITHM = "DSA";
	public final static int KEYSIZE = 512;

	private PrivateKey privateKey = null;
	private PublicKey publicKey = null;

	/**
	 * 设置公共密匙
	 * 
	 * @param hexPublicKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void setPublicKey(String hexPublicKey) throws IOException,
			ClassNotFoundException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		setPublicKey(StringUtils.hexToByte(hexPublicKey));
	}

	/**
	 * 设置公共密匙
	 * 
	 * @param publicKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void setPublicKey(byte publicKey[]) throws IOException,
			ClassNotFoundException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
		KeySpec ks = new X509EncodedKeySpec(publicKey);
		setPublicKey(kf.generatePublic(ks));
	}

	/**
	 * 设置公共密匙
	 * 
	 * @param publicKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void setPublicKey(File publicKey) throws IOException,
			ClassNotFoundException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(publicKey);
			ois = new ObjectInputStream(fis);
			setPublicKey((PublicKey) ois.readObject());
		} finally {
			if (ois != null)
				ois.close();
			if (fis != null)
				fis.close();
		}
	}

	/**
	 * 设置公共密匙
	 * 
	 * @param publicKey
	 */
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * 获取公共密匙
	 * 
	 * @return
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * 获取公共密匙
	 * 
	 * @return
	 */
	public byte[] getPublicKeyToByte() {
		return getPublicKey().getEncoded();
	}

	/**
	 * 获取公共密匙
	 * 
	 * @return
	 */
	public String getPublicKeyToHex() {
		return StringUtils.byteToHex(getPublicKeyToByte());
	}

	/**
	 * 设置私用密匙
	 * 
	 * @param hexPrivateKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void setPrivateKey(String hexPrivateKey) throws IOException,
			ClassNotFoundException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		setPrivateKey(StringUtils.hexToByte(hexPrivateKey));
	}

	/**
	 * 设置私用密匙
	 * 
	 * @param PrivateKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void setPrivateKey(byte PrivateKey[]) throws IOException,
			ClassNotFoundException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
		KeySpec ks = new PKCS8EncodedKeySpec(PrivateKey);
		setPrivateKey(kf.generatePrivate(ks));
	}

	/**
	 * 设置私用密匙
	 * 
	 * @param PrivateKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void setPrivateKey(File PrivateKey) throws IOException,
			ClassNotFoundException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(PrivateKey);
			ois = new ObjectInputStream(fis);
			setPrivateKey((PrivateKey) ois.readObject());
		} finally {
			if (ois != null)
				ois.close();
			if (fis != null)
				fis.close();
		}
	}

	/**
	 * 设置私用密匙
	 * 
	 * @param privateKey
	 */
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	/**
	 * 获取私用密匙
	 * 
	 * @return
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * 获取私用密匙
	 * 
	 * @return
	 */
	public byte[] getPrivateKeyToByte() {
		return getPrivateKey().getEncoded();
	}

	/**
	 * 获取私用密匙
	 * 
	 * @return
	 */
	public String getPrivateKeyToHex() {
		return StringUtils.byteToHex(getPrivateKeyToByte());
	}

	/**
	 * 创建公匙和私匙
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public void createKey() throws NoSuchAlgorithmException {
		createKey(KEYSIZE);
	}

	/**
	 * 创建公匙和私匙
	 * 
	 * @param keySize
	 * @throws NoSuchAlgorithmException
	 */
	public void createKey(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		SecureRandom sr = new SecureRandom();
		kpg.initialize(keySize, sr);
		KeyPair kp = kpg.generateKeyPair();
		setPrivateKey(kp.getPrivate());
		setPublicKey(kp.getPublic());
	}

	/**
	 * 保存公匙到文件
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public File savePublicKey(String path) throws IOException {
		return saveKey(getPublicKey(), path);
	}

	/**
	 * 保存私匙到文件
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public File savePrivateKey(String path) throws IOException {
		return saveKey(getPrivateKey(), path);
	}

	/**
	 * 保存密匙到文件
	 * 
	 * @param key
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public static File saveKey(Key key, String path) throws IOException {
		File f = null;
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			f = new File(path);
			fos = new FileOutputStream(f);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(key);
		} finally {
			if (oos != null)
				oos.close();
			if (fos != null)
				fos.close();
		}
		return f;
	}

	/**
	 * 根据传入数据，进行数据签名，返回十六进制签名字符串
	 * 
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	public String sign(String data) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException {
		return StringUtils.byteToHex(sign(data.getBytes()));
	}

	/**
	 * 根据传入数据，进行数据签名
	 * 
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	public byte[] sign(byte data[]) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException {
		Signature s = Signature.getInstance(ALGORITHM);
		s.initSign(getPrivateKey());
		s.update(data);
		return s.sign();
	}

	/**
	 * 根据签名和数据内容验证正确性
	 * 
	 * @param signature
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(String signature, String data)
			throws InvalidKeyException, SignatureException,
			NoSuchAlgorithmException {
		return verify(StringUtils.hexToByte(signature), data.getBytes());
	}

	/**
	 * 根据签名和数据内容验证正确性
	 * 
	 * @param signature
	 * @param data
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public boolean verify(byte signature[], byte data[])
			throws SignatureException, InvalidKeyException,
			NoSuchAlgorithmException {
		Signature verifyalg = Signature.getInstance(ALGORITHM);
		verifyalg.initVerify(getPublicKey());
		verifyalg.update(data);
		return verifyalg.verify(signature);
	}
}

package org.developerworld.commons.codec.digest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA 密码
 * 
 * @author Roy Huang
 * 
 */
public class RSA {

	public final static String ALGORITHM = "RSA";
	public final static int KEYSIZE = 512;

	private RSAPrivateKey rsaPrivateKey = null;
	private RSAPublicKey rsaPublicKey = null;

	/**
	 * 设置公共密匙
	 * 
	 * @param publicKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void setRSAPublicKey(File rsaPublicKey) throws IOException,
			ClassNotFoundException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(rsaPublicKey);
			ois = new ObjectInputStream(fis);
			setRSAPublicKey((RSAPublicKey) ois.readObject());
		} finally {
			if (ois != null)
				ois.close();
			if (fis != null)
				fis.close();
		}
	}

	public void setRSAPublicKey(RSAPublicKey rsaPublicKey) {
		this.rsaPublicKey = rsaPublicKey;
	}

	public RSAPublicKey getRSAPublicKey() {
		return rsaPublicKey;
	}

	public byte[] getRSAPublicKeyToByte() {
		return getRSAPublicKey().getEncoded();
	}

	/**
	 * 设置私用密匙
	 * 
	 * @param PrivateKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public void setRSAPrivateKey(File rsaPrivateKey) throws IOException,
			ClassNotFoundException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(rsaPrivateKey);
			ois = new ObjectInputStream(fis);
			setRSAPrivateKey((RSAPrivateKey) ois.readObject());
		} finally {
			if (ois != null)
				ois.close();
			if (fis != null)
				fis.close();
		}
	}

	public void setRSAPrivateKey(RSAPrivateKey rsaPrivateKey) {
		this.rsaPrivateKey = rsaPrivateKey;
	}

	public RSAPrivateKey getRSAPrivateKey() {
		return rsaPrivateKey;
	}

	public byte[] getRSAPrivateKeyToByte() {
		return getRSAPrivateKey().getEncoded();
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
		KeyPair kp = createKeyPair(keySize);
		setRSAPublicKey((RSAPublicKey) kp.getPublic());
		setRSAPrivateKey((RSAPrivateKey) kp.getPrivate());
	}

	/**
	 * 创建密钥对
	 * 
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair createKeyPair(int keySize)
			throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
		SecureRandom sr = new SecureRandom();
		kpg.initialize(keySize, sr);
		return kpg.generateKeyPair();
	}

	/**
	 * 保存公匙到文件
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public File saveRSAPublicKey(String path) throws IOException {
		return saveKey(getRSAPublicKey(), path);
	}

	/**
	 * 保存私匙到文件
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public File saveRSAPrivateKey(String path) throws IOException {
		return saveKey(getRSAPrivateKey(), path);
	}

	/**
	 * 保存密匙到文件
	 * 
	 * @param key
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public static File saveKey(Object key, String path) throws IOException {
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

	public byte[] encrypt(byte data[]) throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException {
		return encrypt(rsaPublicKey, data);
	}

	public static byte[] encrypt(RSAPublicKey rsaPublicKey, byte data[])
			throws InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException,
			NoSuchPaddingException {
		return work(Cipher.ENCRYPT_MODE, rsaPublicKey, data);
	}

	public byte[] decrypt(byte data[]) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		return decrypt(rsaPrivateKey, data);
	}

	public static byte[] decrypt(RSAPrivateKey rsaPrivateKey, byte data[])
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		return work(Cipher.DECRYPT_MODE, rsaPrivateKey, data);
	}

	private static byte[] work(int mode, Key key, byte data[])
			throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException {
		Cipher c = Cipher.getInstance(ALGORITHM);
		c.init(mode, key);// 指定解密模式
		return c.doFinal(data);
	}

}

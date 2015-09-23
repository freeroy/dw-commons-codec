package org.developerworld.commons.codec.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.developerworld.commons.lang.StringUtils;

/**
 * @version 20090716
 * @author Roy.Huang
 * 
 */
public class DES {

	public final static String ALGORITHM = "DES";

	/**
	 * 创建十六进制密匙
	 * 
	 * @deprecated 不建议使用该方法创建key
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String createHexKey() throws NoSuchAlgorithmException {
		return StringUtils.byteToHex(createKey());
	}

	/**
	 * 创建密匙
	 * 
	 * @deprecated 不建议使用该方法创建key
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] createKey() throws NoSuchAlgorithmException {
		// DES算法要求有一个可信任的随机数源
		SecureRandom sr = new SecureRandom();
		// 为我们选择的DES算法生成一个KeyGenerator对象
		KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
		kg.init(sr);
		// 生成密匙
		SecretKey key = kg.generateKey();
		return key.getEncoded();
	}

	/**
	 * 根据key进行数据加密,返回加密数据
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String encrypt(String key, String data)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		return StringUtils.byteToHex(encrypt(key.getBytes(),
				data.getBytes()));
	}

	/**
	 * 加密数据
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte key[], byte data[])
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		return work(key, data, Cipher.ENCRYPT_MODE);
	}

	/**
	 * 根据密匙和数据,解密数据
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 */
	public static String decrypt(String key, String data)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException {
		return new String(decrypt(key.getBytes(),
				StringUtils.hexToByte(data)));
	}

	/**
	 * 解密数据
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 */
	public static byte[] decrypt(byte key[], byte data[])
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException {
		return work(key, data, Cipher.DECRYPT_MODE);
	}

	/**
	 * 根据模式号进行加密或解密操作
	 * 
	 * @param key
	 * @param data
	 * @param mode
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private static byte[] work(byte key[], byte data[], int mode)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		// DES算法要求有一个可信任的随机数源
		SecureRandom sr = new SecureRandom();
		// 从原始密匙数据创建一个DESKeySpec对象
		DESKeySpec dks = new DESKeySpec(key);
		// 创建一个密匙工厂，然后用它把DESKeySpec对象转换成一个SecretKey对象
		SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
		SecretKey sk = skf.generateSecret(dks);
		// Cipher对象实际完成解密操作
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		// 用密匙初始化Cipher对象
		cipher.init(mode, sk, sr);
		// 返回解密数据
		return cipher.doFinal(data);
	}
}

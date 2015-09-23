package org.developerworld.commons.codec.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;
import org.developerworld.commons.lang.StringUtils;

/**
 * @version 20090716
 * @author Roy.Huang
 * 
 */
public class AES {

	public final static String ALGORITHM = "AES";
	public final static String ALGORITHM_ECB = "AES/ECB/PKCS5Padding";
	public final static String ALGORITHM_CBC = "AES/CBC/PKCS5Padding";

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
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String encrypt(String key, String data)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		return encrypt(key, data, ALGORITHM);
	}

	/**
	 * 加密数据
	 * 
	 * @param key
	 * @param data
	 * @param algorithmMode
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String encrypt(String key, String data, String algorithmMode)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		return StringUtils.byteToHex(encrypt(key.getBytes(), data.getBytes(),algorithmMode));
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
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] encrypt(byte key[], byte data[])
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		return encrypt(key, data, ALGORITHM);
	}

	/**
	 * 加密数据
	 * 
	 * @param key
	 * @param data
	 * @param algorithmMode
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] encrypt(byte key[], byte data[], String algorithmMode)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
		kgen.init(128, new SecureRandom(key));
		SecretKey secretKey = kgen.generateKey();
		byte[] enCodeFormat = secretKey.getEncoded();
		SecretKeySpec sks = new SecretKeySpec(enCodeFormat, ALGORITHM);
		Cipher cipher = Cipher.getInstance(algorithmMode);// 创建密码器
		if (algorithmMode.equals(ALGORITHM_CBC))
			cipher.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(
					ArrayUtils.subarray(key, 0, 16)));// 初始化
		else
			cipher.init(Cipher.ENCRYPT_MODE, sks);// 初始化
		return cipher.doFinal(data);
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
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String decrypt(String key, String data)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		return decrypt(key, data, ALGORITHM);
	}

	/**
	 * 解密数据
	 * 
	 * @param key
	 * @param data
	 * @param algorithmMode
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String decrypt(String key, String data, String algorithmMode)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		return new String(decrypt(key.getBytes(), StringUtils.hexToByte(data),algorithmMode));
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
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] decrypt(byte key[], byte data[])
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException,
			InvalidAlgorithmParameterException {
		return decrypt(key, data, ALGORITHM);
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
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] decrypt(byte key[], byte data[], String algorithmMode)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException {
		KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
		kgen.init(128, new SecureRandom(key));
		SecretKey secretKey = kgen.generateKey();
		byte[] enCodeFormat = secretKey.getEncoded();
		SecretKeySpec sks = new SecretKeySpec(enCodeFormat, ALGORITHM);
		Cipher cipher = Cipher.getInstance(algorithmMode);// 创建密码器
		if (algorithmMode.equals(ALGORITHM_CBC))
			cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(
					ArrayUtils.subarray(key, 0, 16)));// 初始化
		else
			cipher.init(Cipher.DECRYPT_MODE, sks);// 初始化
		return cipher.doFinal(data);
	}
}

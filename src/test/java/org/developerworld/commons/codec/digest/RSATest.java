package org.developerworld.commons.codec.digest;

import org.junit.Assert;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

public class RSATest {

	@Test
	public void test() throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchPaddingException {
		String data = "123";
		KeyPair kp = RSA.createKeyPair(RSA.KEYSIZE);
		RSAPublicKey rsaPublicKey = (RSAPublicKey) kp.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kp.getPrivate();

		System.out.println(rsaPublicKey.getModulus());
		System.out.println(rsaPublicKey.getPublicExponent());
		System.out.println(new BigInteger(data.getBytes()).modPow(
				rsaPublicKey.getPublicExponent(), rsaPublicKey.getModulus()));
		System.out.println(new BigInteger(rsaPublicKey.getEncoded()));

		byte data2[] = RSA.encrypt(rsaPublicKey, data.getBytes());

		byte data3[] = RSA.decrypt(rsaPrivateKey, data2);
		System.out.println(new String(data3));

		Assert.assertTrue(true);
	}

}

package org.developerworld.commons.codec.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Test;

public class DESTest {

	@Test
	public void test() throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException {
		String data1 = "adfadsf撒旦法倒萨分";
		String key = "ABCDEFGH";

		System.out.println("原数据为：" + data1);
		System.out.println("密匙为：" + key);

		String data2 = DES.encrypt(key, data1);
		System.out.println("加密后数据为：" + data2);

		String data3 = DES.decrypt(key, data2);
		System.out.println("解密后数据为：" + data3);
		Assert.assertEquals(data1, data3);
	}

}

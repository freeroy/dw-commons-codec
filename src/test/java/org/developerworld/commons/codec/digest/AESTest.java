package org.developerworld.commons.codec.digest;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Test;

public class AESTest {

	@Test
	public void test() throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		String data1 = "阿迪是发送发达撒地方";
		String key = "ABCDABCDABCDABCD12";

		System.out.println("原数据为：" + data1);
		System.out.println("密匙为：" + key);

		String data2 = AES.encrypt(key, data1,AES.ALGORITHM_ECB);
		System.out.println("加密后数据为：" + data2);

		String data3 = AES.decrypt(key, data2,AES.ALGORITHM_ECB);
		System.out.println("解密后数据为：" + data3);
		Assert.assertEquals(data1, data3);
	}

}

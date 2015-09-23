package org.developerworld.commons.codec.digest;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.developerworld.commons.lang.StringUtils;
import org.junit.Assert;
import org.junit.Test;

public class DigestUtilsTest {

	@Test
	public void test() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		String code="13570424264";
		MessageDigest md=MessageDigest.getInstance("MD5");
		md.update(code.getBytes());
		byte[] md5b=md.digest();
		System.out.println(StringUtils.byteToHex(md5b));
		System.out.println("---------");
		System.out.println(DigestUtils.md5Hex(code));
		
		Assert.assertTrue(true);
	}
}

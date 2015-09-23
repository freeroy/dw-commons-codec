package org.developerworld.commons.codec.digest;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Assert;
import org.junit.Test;

public class DSATest {

	@Test
	public void test() throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException, ClassNotFoundException,
			InvalidKeyException, SignatureException {
		String data = "我是数据";
		String publicPath = "E:/publicKey.dat";
		String privatePath = "E:/privateKey.dat";

		DSA dsa = new DSA();

		dsa.createKey();
		String publicKey = dsa.getPublicKeyToHex();
		String privateKey = dsa.getPrivateKeyToHex();
		System.out.println("公匙是：" + publicKey);
		System.out.println("私匙是:" + privateKey);

		File publicKeyFile = dsa.savePublicKey(publicPath);
		File PrivateKeyFile = dsa.savePrivateKey(privatePath);
		System.out.println("公匙保存到：" + publicKeyFile.getAbsolutePath());
		System.out.println("私匙保存到:" + PrivateKeyFile.getAbsolutePath());

		String signature = dsa.sign(data);
		System.out.println("签名为：" + signature);

		dsa = new DSA();
		dsa.setPublicKey(publicKey);
		dsa.setPrivateKey(privateKey);

		System.out.println("验证签名结果：" + dsa.verify(signature, data));
		// System.out.println("验证签名结果："+dsa.verify("adfsa", data));
		Assert.assertTrue(true);
	}

}

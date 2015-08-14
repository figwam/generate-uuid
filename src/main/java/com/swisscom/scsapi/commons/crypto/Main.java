package com.swisscom.scsapi.commons.crypto;

import java.io.File;
import java.net.URLEncoder;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

public class Main {
	/**
	 * Source code example on how to encrypt a secret with a public key.
	 * 
	 * @PARAM aSecret the text to encrypt and URL encode
	 * @RETURN The URL encoded and encrypted secret
	 */
	public String runDemo(final String aSecret) {
	  String privateKeyBase64 = readKey(new File("../keys/myservice/prod/private.key"));
	  String encryptedSecret = RsaCryptoHelper.encryptValueWithPrivateKey(privateKeyBase64, aSecret);
	  return URLEncoder.encode(encryptedSecret);  //used as query parameter value in the URL
	}

	/**
	 * Reads the key from a file.
	 * 
	 * @PARAM aFilepathToKey the filepath to the private key
	 * @RETURN Base64 encoded private key
	 */
	private String readKey(File aFilepathToKey) {
		byte[] key = null;
		try {
			key = FileUtils.readFileToByteArray(aFilepathToKey);
		} catch (Exception exception) { 
			exception.printStackTrace();
		}
		return Base64.encodeBase64String(key);
	}
	
	public static void main(String[] args) {
		Main m = new Main();
		System.out.println(m.runDemo("28:"+System.currentTimeMillis()));
	}
}

package com.tazouxme.ecdh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import com.tazouxme.ecdh.entity.ExchangeKeyEntity;
import com.tazouxme.ecdh.entity.ProtectedEntity;

public class ExchangeKeyService {
	
	public ExchangeKeyService() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	// should be safely stored
	private SecretKey secretKey;
	
	@OPTIONS
	@Path("/exchange")
	@Produces(MediaType.APPLICATION_JSON)
	public Response init(@Context HttpServletRequest request) {
		String clientPublicKeyEncoded = request.getHeader("x-public-key");
		
		try {
			PublicKey clientPublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.decode(clientPublicKeyEncoded)));
			KeyPair keys = generateKeys();
			
			PublicKey publicKey = keys.getPublic();
			PrivateKey privateKey = keys.getPrivate();
			
			secretKey = generateSharedSecret(privateKey, clientPublicKey);
			
			return Response.ok(new ExchangeKeyEntity(200, "OK", new String(Base64.encode(publicKey.getEncoded())))).build();
		} catch (Exception e) {
			return Response.status(401).entity(new ExchangeKeyEntity(401, e.getMessage(), "")).build();
		}
	}
	
	@GET
	@Path("/exchange")
	@Produces(MediaType.APPLICATION_JSON)
	public Response get() {
		if (secretKey == null) {
			return Response.status(417).entity(new ExchangeKeyEntity(417, "Key not generated", "")).build();
		}
		
		try {
			return Response.ok(encrypt(secretKey, "Hello World")).build();
		} catch (Exception e) {
			return Response.status(500).entity(new ExchangeKeyEntity(500, e.getMessage(), "")).build();
		}
	}
	
	@POST
	@Path("/exchange")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response post(ProtectedEntity encryptedResource) {
		if (secretKey == null) {
			return Response.status(417).entity(new ExchangeKeyEntity(417, "Key not generated", "")).build();
		}
		
		try {
			String decryptedResource = decrypt(secretKey, encryptedResource);
			return Response.ok(encrypt(secretKey, decryptedResource)).build();
		} catch (Exception e) {
			return Response.status(500).entity(new ExchangeKeyEntity(500, e.getMessage(), "")).build();
		}
	}
	
	private static KeyPair generateKeys() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("P-384"));
        
        return keyPairGenerator.generateKeyPair();
    }
	
	private static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret("AES");
    }
	
	private static ProtectedEntity encrypt(SecretKey key, String decryptedResource) throws Exception {
		byte[] iv = generateRandomBytes(16);
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		
		String encryptedResource = new String(Base64.encode(cipher.doFinal(decryptedResource.getBytes())));
		String encryptedIv = new String(Base64.encode(iv));
		
		return new ProtectedEntity(encryptedIv, encryptedResource);
    }
	
	private static String decrypt(SecretKey key, ProtectedEntity encryptedResource) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.decode(encryptedResource.getIv())));
		
		return new String(cipher.doFinal(Base64.decode(encryptedResource.getText())));
    }
	
	private static byte[] generateRandomBytes(int length) {
		byte[] bytes = new byte[length];
		Random r = new Random();
		r.nextBytes(bytes);
		
		return bytes;
	}

}

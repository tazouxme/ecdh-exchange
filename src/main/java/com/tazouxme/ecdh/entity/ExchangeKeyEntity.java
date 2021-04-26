package com.tazouxme.ecdh.entity;

public class ExchangeKeyEntity {
	
	public int code;
	public String message;
	public String publicKey;
	
	public ExchangeKeyEntity() {
		this(500, "Server error", "");
	}
	
	public ExchangeKeyEntity(int code, String message, String publicKey) {
		this.code = code;
		this.message = message;
		this.publicKey = publicKey;
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

}

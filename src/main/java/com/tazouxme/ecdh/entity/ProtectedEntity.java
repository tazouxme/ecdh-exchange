package com.tazouxme.ecdh.entity;

public class ProtectedEntity {
	
	private String iv;
	private String text;
	
	public ProtectedEntity() {
		this("", "");
	}
	
	public ProtectedEntity(String iv, String text) {
		this.iv = iv;
		this.text = text;
	}
	
	public String getIv() {
		return iv;
	}
	
	public void setIv(String iv) {
		this.iv = iv;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

}

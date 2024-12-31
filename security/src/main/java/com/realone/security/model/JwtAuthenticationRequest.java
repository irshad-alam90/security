package com.realone.security.model;

public class JwtAuthenticationRequest {

	private String userId;
	private String password;
	public JwtAuthenticationRequest() {

	}
	public JwtAuthenticationRequest(String userId, String password) {
		this.userId = userId;
		this.password = password;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	@Override
	public String toString() {
		return "JwtAuthenticationRequest [userId=" + userId + ", password=" + password + "]";
	}
	
	
}

package com.realone.security.model;

public class JwtAuthenticationResponse {

	private String token;
	private String username;
	public JwtAuthenticationResponse() {
		super();
	}
	public JwtAuthenticationResponse(String token, String username) {
		super();
		this.token = token;
		this.username = username;
	}
	@Override
	public String toString() {
		return "JwtAuthenticationResponse [token=" + token + ", username=" + username + "]";
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	
}

package com.realone.security.service;


import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.realone.realonemodel.model.users.User;
import com.realone.realonemodel.repository.users.UserRepository;
import com.realone.security.model.JwtUserDetails;

@Service
public class JwtUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User userInfo = userRepository.findByUserId(username);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities = Arrays.stream(userInfo.getRoles().split(","))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
		JwtUserDetails jwtUserDetails = new JwtUserDetails(userInfo.getUserId(), userInfo.getName(), userInfo.getEmail(), userInfo.getPassword(),authorities);
		return jwtUserDetails;
	}
	
	/*
	 * private List<GrantedAuthority> mapToGrantedAuthorities(Set<GrantedAuthority>
	 * authorities){ return authorities.stream().map(authority -> new
	 * SimpleGrantedAuthority(authority)) .collect(Collectors.toList()); }
	 */
}

package com.example.securitytestback.login.service;

import com.example.securitytestback.domain.User;
import com.example.securitytestback.domain.UserRepository;
import com.example.securitytestback.login.dto.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    // DB에서 조회
    User user = userRepository.findByUsername(username);

    if (user != null) {

      // UserDetails에 담아서 return 하면 AuthenticationManager가 검증함
      return new CustomUserDetails(user);
    }

    return null;
  }
}

package com.example.securitytestback.register.service;

import com.example.securitytestback.domain.User;
import com.example.securitytestback.domain.UserRepository;
import com.example.securitytestback.global.dto.ApiResponse;
import com.example.securitytestback.register.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegisterService {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  /**
   * 회원가입
   */
  public ApiResponse<String> register(RegisterRequest request) {

    // 1. 중복 아이디 검증
    if (userRepository.existsByUsername(request.getUsername())) {
      log.error("이미 사용중인 아이디 입니다. 요청 아이디: {}", request.getUsername());
      return ApiResponse.error(409, "이미 존재하는 아이디입니다.");
    }

    // 2. 비밀번호 재확인
    if (!request.getPassword().equals(request.getPasswordConfirm())) {
      log.error("비밀번호가 일치하지 않습니다.");
      return ApiResponse.error(400, "비밀번호가 일치하지 않습니다.");
    }

    // 3. 회원가입 완료
    userRepository.save(User.builder()
        .username(request.getUsername())
        .password(bCryptPasswordEncoder.encode(request.getPassword()))
        .name(request.getName())
        .email(request.getEmail())
        .build());

    log.info("회원가입 완료");
    return ApiResponse.success(200, "회원가입이 완료되었습니다.");
  }
}

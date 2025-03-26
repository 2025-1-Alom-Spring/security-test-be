package com.example.securitytestback.global.filter;

import com.example.securitytestback.global.dto.ApiResponse;
import com.example.securitytestback.global.exception.CustomException;
import com.example.securitytestback.global.exception.ErrorCode;
import com.example.securitytestback.global.util.JwtUtil;
import com.example.securitytestback.login.dto.CustomUserDetails;
import com.example.securitytestback.login.dto.LoginRequest;
import com.example.securitytestback.login.dto.LoginResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

  private final JwtUtil jwtUtil;
  private final AuthenticationManager authenticationManager;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

    // 클라이언트 요청에서 username, password 추출
    try {
      // 요청 본문에서 JSON 데이터를 파싱
      LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

      String username = loginRequest.getUsername();
      String password = loginRequest.getPassword();

      // 스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
      UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

      // token에 담은 검증을 위한 AuthenticationManager로 전달
      return authenticationManager.authenticate(authToken);
    } catch (IOException e) {
      log.error("JSON 파싱 중 오류 발생");
      throw new CustomException(ErrorCode.INVALID_REQUEST);
    }
  }

  //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
    // UserDetails
    CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

    // AccessToken 발급
    String accessToken = jwtUtil.createAccessToken(customUserDetails);

    // RefreshToken 발급
    String refreshToken = jwtUtil.createRefreshToken(customUserDetails);

    // 헤더에 AccessToken 추가
    response.addHeader("Authorization", "Bearer " + accessToken);

    // 쿠키에 refreshToken 추가
    Cookie cookie = new Cookie("refreshToken", refreshToken);
    cookie.setHttpOnly(true); // HttpOnly 설정
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setMaxAge((int) (jwtUtil.getRefreshExpirationTime() / 1000)); // 쿠키 maxAge는 초 단위 이므로, 밀리초를 1000으로 나눔
    response.addCookie(cookie);

    // 로그인에 성공하면 유저 정보 반환
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");

    // 반환할 유저 정보
    LoginResponse loginResponse = LoginResponse.builder()
        .username(customUserDetails.getUsername())
        .name(customUserDetails.getName())
        .build();

    ApiResponse<LoginResponse> apiResponse = new ApiResponse<>(loginResponse, "로그인 성공");
    response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    response.setStatus(HttpServletResponse.SC_OK);
  }

  //로그인 실패시 실행하는 메소드
  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {

    log.error("로그인 실패: {}", failed.getMessage());

    // 응답 설정
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");

    ApiResponse<Object> apiResponse = new ApiResponse<>(401, "아이디 또는 비밀번호가 일치하지 않습니다.");
    response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
  }
}

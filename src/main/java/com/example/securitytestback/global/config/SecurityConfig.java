package com.example.securitytestback.global.config;

import com.example.securitytestback.global.filter.JwtFilter;
import com.example.securitytestback.global.filter.LoginFilter;
import com.example.securitytestback.global.util.JwtUtil;
import java.util.Arrays;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtUtil jwtUtil;
  private final AuthenticationConfiguration authenticationConfiguration;

  /**
   * 허용된 CORS Origin 목록
   */
  private static final String[] ALLOWED_ORIGINS = {
      "http://localhost:5173"
  };

  /**
   * Security Filter Chain 설정
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // 로그인 경로를 설정하기 위해 LoginFilter 생성
    LoginFilter loginFilter = new LoginFilter(jwtUtil, authenticationManager(authenticationConfiguration));
    loginFilter.setFilterProcessesUrl("/api/auth/login");

    return http
        // cors 설정
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        // csrf disable
        .csrf(AbstractHttpConfigurer::disable)
        // http basic 인증 방식 disable
        .httpBasic(AbstractHttpConfigurer::disable)
        // form 로그인 방식 disable
        .formLogin(AbstractHttpConfigurer::disable)
        // 경로별 인가 작업
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/api/user/register", "/api/auth/login").permitAll()
            .anyRequest().authenticated()
        )
        // 세션 설정 STATELESS
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .addFilterBefore(
            new JwtFilter(jwtUtil),
            LoginFilter.class
        )
        .addFilterAt(
            loginFilter,
            UsernamePasswordAuthenticationFilter.class
        )
        .build();
  }

  /**
   * 인증 메니저 설정
   */
  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration)
      throws Exception {

    return authenticationConfiguration.getAuthenticationManager();
  }

  /**
   * CORS 설정 소스 빈
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(Arrays.asList(ALLOWED_ORIGINS));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowCredentials(true);
    configuration.setAllowedHeaders(Collections.singletonList("*"));
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
    urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", configuration);
    return urlBasedCorsConfigurationSource;
  }

  /**
   * 비밀번호 인코더 빈 (BCrypt)
   */
  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
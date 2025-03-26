package com.example.securitytestback.global.dto;

import lombok.Getter;

@Getter
public class ApiResponse<T> {
  private T user; // 성공 시 사용 (실패 시 null)
  private int status; // 실패 시 사용 (성공 시 생략 가능)
  private final String message;

  // 성공 응답 생성자
  public ApiResponse(T user, String message) {
    this.user = user;
    this.message = message;
  }

  // 실패 응답 생성자
  public ApiResponse(int status, String message) {
    this.status = status;
    this.message = message;
  }

  // 성공 응답을 위한 정적 팩토리 메서드 (간편 사용)
  public static <T> ApiResponse<T> success(int status, String message) {
    return new ApiResponse<>(status, message);
  }

  // 실패 응답을 위한 정적 팩토리 메서드
  public static <T> ApiResponse<T> error(int status, String message) {
    return new ApiResponse<>(status, message);
  }
}

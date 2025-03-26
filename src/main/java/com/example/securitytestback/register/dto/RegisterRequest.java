package com.example.securitytestback.register.dto;

import lombok.Getter;

@Getter
public class RegisterRequest {
  private String username;
  private String password;
  private String passwordConfirm;
  private String name;
  private String email;
}

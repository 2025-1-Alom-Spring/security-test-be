package com.example.securitytestback.register.controller;

import com.example.securitytestback.global.dto.ApiResponse;
import com.example.securitytestback.register.dto.RegisterRequest;
import com.example.securitytestback.register.service.RegisterService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RegisterController {

  private final RegisterService registerService;

  @PostMapping("/api/user/register")
  public ApiResponse<String> register(@RequestBody RegisterRequest request) {
    return registerService.register(request);
  }
}

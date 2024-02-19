package com.hprocoder.customsecurityheader.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.MimeTypeUtils;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@AllArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private static final Logger LOGGER = LogManager.getLogger(CustomAuthenticationFailureHandler.class);

    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        LOGGER.debug("Call onAuthenticationFailure : user not authenticated");

        Map<String, Object> data = new HashMap<>();
        data.put("timestamp", LocalDateTime.now());
        data.put("message", exception.getMessage());

        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.getOutputStream().println(objectMapper.writeValueAsString(data));
        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
    }
}

package com.hprocoder.customsecurityheader.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1")
public class HelloController {

    @PreAuthorize("hasAuthority('GUEST')")
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello(){
        return new ResponseEntity<>( "Hello", HttpStatus.OK);
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/hi")
    public ResponseEntity<String> sayHay(){
        return new ResponseEntity<>( "Hi !", HttpStatus.OK);
    }
}

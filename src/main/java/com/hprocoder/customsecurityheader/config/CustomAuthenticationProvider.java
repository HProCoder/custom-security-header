package com.hprocoder.customsecurityheader.config;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;

@NoArgsConstructor
public class CustomAuthenticationProvider extends PreAuthenticatedAuthenticationProvider {


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object userId = authentication.getCredentials();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

       if(StringUtils.isBlank(username)){
            throw new UsernameNotFoundException("user not found");
        }

       if(userId == null || StringUtils.isBlank(userId.toString())){
            throw new BadCredentialsException("Invalid credentials");
        }

        if(authorities.isEmpty()) {
            throw new AccessDeniedException("Invalid empty autorities");
        }

        return new PreAuthenticatedAuthenticationToken(username, userId, authorities);
    }
}

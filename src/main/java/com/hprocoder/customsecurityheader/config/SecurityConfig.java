package com.hprocoder.customsecurityheader.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.servlet.Filter;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(request ->
                        request.requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                                .permitAll()
                        .anyRequest().authenticated()).formLogin(Customizer.withDefaults())
                .addFilterBefore(getFilter(), AnonymousAuthenticationFilter.class)
                .authenticationManager(authenticationManager())
                .exceptionHandling(c -> c.accessDeniedHandler(customAccessDeniedHandler(objectMapper())));

        http.csrf(csrf -> csrf.ignoringRequestMatchers("/**"));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(authenticationProvider());
    }

    @Bean
    public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService(){
        return new PreAuthenticatedGrantedAuthoritiesUserDetailsService();
    }
    @Bean
    public CustomAuthenticationProvider authenticationProvider() {
        CustomAuthenticationProvider provider = new CustomAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(userDetailsService());
        return provider;
    }

    @Bean
    public RequestMatcher getRequestMatchers(){
        return new OrRequestMatcher(new AntPathRequestMatcher("/**"));
    }
    private Filter getFilter(){
        return customAuthenticationProcessingFilter(customAuthenticationFailureHandler(objectMapper()));
    }

    @Bean
    CustomAuthenticationProcessingFilter customAuthenticationProcessingFilter(AuthenticationFailureHandler authenticationFailureHandler){
        return new CustomAuthenticationProcessingFilter(getRequestMatchers(),authenticationManager(), authenticationFailureHandler);
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler(ObjectMapper objectMapper){
        return new CustomAuthenticationFailureHandler(objectMapper);
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler(ObjectMapper objectMapper){
        return new CustomAccessDeniedHandler(objectMapper);
    }

    @Bean
    public ObjectMapper objectMapper(){
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return objectMapper;
    }


}

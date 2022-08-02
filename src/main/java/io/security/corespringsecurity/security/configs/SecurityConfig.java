package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
    private final AccessDeniedHandler accessDeniedHandler;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(
            AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource,
            @Qualifier("customAuthenticationSuccessHandler") AuthenticationSuccessHandler authenticationSuccessHandler,
            @Qualifier("customAuthenticationFailureHandler") AuthenticationFailureHandler authenticationFailureHandler,
            @Qualifier("customAccessDeniedHandler") AccessDeniedHandler accessDeniedHandler,
            @Qualifier("customAuthenticationProvider") AuthenticationProvider authenticationProvider) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider);
    }

    /*
        정적 파일들이 보안필터를 거치지 않도록 하는 설정
     */
    @Override
    public void configure(WebSecurity web) {
        web.
                ignoring().
                requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                authorizeRequests().
                antMatchers("/", "/users", "user/login/**", "/login*").permitAll().
                antMatchers("/mypage").hasRole("USER").
                antMatchers("/messages").hasRole("MANAGER").
                antMatchers("/config").hasRole("ADMIN").
                anyRequest().
                authenticated().
            and().
                formLogin().
                loginPage("/login").
                loginProcessingUrl("/login_proc").
                authenticationDetailsSource(authenticationDetailsSource).
                defaultSuccessUrl("/").
                successHandler(authenticationSuccessHandler).
                failureHandler(authenticationFailureHandler).
                permitAll().
            and().
                exceptionHandling().
                accessDeniedHandler(accessDeniedHandler());

    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler customAccessDeniedHandler =
                (CustomAccessDeniedHandler) accessDeniedHandler;
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }
}

package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.demo.common.Constants;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

@Component
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                                    throws IOException, ServletException {

        String token = req.getHeader(Constants.HEADER_STRING);

        if (token == null || !token.startsWith(Constants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        } else {
            String user = JWT.require(HMAC512(Constants.SECRET.getBytes())).build()
                             .verify(token.replace(Constants.TOKEN_PREFIX, ""))
                             .getSubject();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(req, res);
        }
    }
}
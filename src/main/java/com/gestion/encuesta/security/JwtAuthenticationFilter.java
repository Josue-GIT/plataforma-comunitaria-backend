package com.gestion.encuesta.security;

import com.gestion.encuesta.service.JwtService;
import com.gestion.encuesta.service.UserDetailServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailServiceImpl userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailServiceImpl userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }


    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("No se encontró el encabezado de autorización o el formato no es válido");
            filterChain.doFilter(request,response);
            return;
        }
        String token = authHeader.substring(7);
        System.out.println("Token JWT encontrado: " + token);
        String username = jwtService.extracUsername(token);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            System.out.println("Nombre de usuario extraído del token: " + username);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (jwtService.isValid(token,userDetails)){
                System.out.println("El token JWT es válido para el usuario: " + username);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null , userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                System.out.println("El token JWT no es válido para el usuario: " + username);
            }
        } else {
            System.out.println("No se pudo extraer el nombre de usuario del token o la autenticación ya está establecida");
        }
        filterChain.doFilter(request,response);


    }
}

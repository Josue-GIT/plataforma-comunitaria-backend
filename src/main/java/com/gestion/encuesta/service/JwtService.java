package com.gestion.encuesta.service;

import com.gestion.encuesta.model.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "50bcf07657dca9382b91b159ea98b241098b4cef65a31ece35461b93c8eec624";


    public String extracUsername(String token) {
        System.out.println("Extrayendo nombre de usuario del token: " + token);
        return extractClaim(token,Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails usuario) {
        String username = extracUsername(token);
        boolean isExpired = isTokenExpired(token);
        System.out.println("Validando token para el usuario: " + username);
        System.out.println("¿El token ha expirado? " + isExpired);
        boolean isValid = username.equals(usuario.getUsername()) && !isExpired;
        System.out.println("El token es válido? " + isValid);
        return isValid;
    }


    private boolean isTokenExpired(String token) {
        System.out.println("Verificando si el token ha expirado: " + token);
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        System.out.println("Extrayendo fecha de expiración del token: " + token);
        return extractClaim(token, Claims::getExpiration);
    }


    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        System.out.println("Extrayendo reclamo del token: " + token);
        Claims claims = extractAllClaims(token);
        return  resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        System.out.println("Extrayendo todos los reclamos del token: " + token);
        return Jwts.parser()
                .verifyWith(getSinginKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(Usuario usuario){
        System.out.println("Generando token para el usuario: " + usuario.getUsername());
        String token = Jwts.builder()
                .subject(usuario.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+3600000))
                .signWith(getSinginKey())
                .compact();
        System.out.println("Token generado: " + token);
        return token;

    }

    private SecretKey getSinginKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

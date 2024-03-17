package com.gestion.encuesta.repository;

import com.gestion.encuesta.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query("SELECT t FROM Token t WHERE t.usuario.id = :userId AND t.loggedOut = false")
    List<Token> findAllTokenByUser(@Param("userId") Long userId);

    Optional<Token> findByToken(String token);
}

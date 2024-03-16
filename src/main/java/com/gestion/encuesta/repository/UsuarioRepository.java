package com.gestion.encuesta.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.gestion.encuesta.model.Usuario;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long>{
	Usuario findByUsernameAndPassword(String username, String password);
	Optional<Usuario> findByUsername(String username);

	boolean existsByUsername(String username);

	boolean existsByEmail(String email);
}

package com.gestion.encuesta.service;

import com.gestion.encuesta.model.Usuario;
import com.gestion.encuesta.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService {

    @Autowired
    UsuarioRepository usuarioRepository;

    public Usuario guardarUsuario(Usuario usuario){
        usuarioRepository.save(usuario);
        return usuario;
    }

}
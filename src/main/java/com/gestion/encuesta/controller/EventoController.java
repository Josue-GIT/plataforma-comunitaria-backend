package com.gestion.encuesta.controller;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

import com.gestion.encuesta.model.Proyecto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.gestion.encuesta.model.Evento;
import com.gestion.encuesta.service.EventoService;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/eventos")
@CrossOrigin("*")
public class EventoController {
	@Autowired
    private EventoService eventoService;
    //comentario de prueba
    @GetMapping("/listar")
    public List<Evento> listarEventos() {
        return eventoService.obtenerTodosLosEventos();
    }
    
    @GetMapping("/listar/{id}")
    public ResponseEntity<?> listarEventoPorId(@PathVariable Long id) {
        Evento evento = eventoService.obtenerEventoPorId(id);

        if (evento != null) {
            return ResponseEntity.ok(evento);
        }else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping(value = "/guardar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> guardarEvento(@RequestParam("img") String imgString64,
                                           @RequestParam("titulo") String titulo,
                                           @RequestParam("descripcion") String descripcion,
                                           @RequestParam("fechaHora") String fechaHora,
                                           @RequestParam("ubicacion") String ubicacion) {
        try {
            if (imgString64 == null || imgString64.isEmpty()) {
                return ResponseEntity.badRequest().body("La imagen es obligatoria");
            }

            if (titulo == null || titulo.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo título es obligatorio");
            }

            if (descripcion == null || descripcion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo descripción es obligatorio");
            }

            if (fechaHora == null || fechaHora.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo fechaHora es obligatorio");
            }

            if (ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo ubicación es obligatorio");
            }

            Evento evento = new Evento();
            evento.setTitulo(titulo);
            evento.setDescripcion(descripcion);
            evento.setFechaHora(fechaHora);
            evento.setUbicacion(ubicacion);
            evento.setImg(imgString64);
            eventoService.guardarEvento(evento);

            return ResponseEntity.ok().body("{\"message\": \"Evento guardado exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar el archivo: " + e.getMessage());
        }
    }

    @PutMapping(value = "/editar/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> editarEvento(@PathVariable Long id,
                                          @RequestParam(value = "img") String imgString64,
                                          @RequestParam("titulo") String titulo,
                                          @RequestParam("descripcion") String descripcion,
                                          @RequestParam("fechaHora") String fechaHora,
                                          @RequestParam("ubicacion") String ubicacion) {
        try {
            Evento eventoExistente = eventoService.obtenerEventoPorId(id);
            if (eventoExistente == null) {
                return ResponseEntity.badRequest().body("El evento a editar no existe");
            }

            if (titulo == null || titulo.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El título del evento no puede estar en blanco");
            }

            if (fechaHora == null) {
                return ResponseEntity.badRequest().body("La fecha y hora del evento no pueden ser nulas");
            }

            if (descripcion == null || descripcion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("La descripción del evento no puede estar en blanco");
            }

            if (ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("La ubicación del evento no puede estar en blanco");
            }

            eventoExistente.setTitulo(titulo);
            eventoExistente.setDescripcion(descripcion);
            eventoExistente.setFechaHora(fechaHora);
            eventoExistente.setUbicacion(ubicacion);
            eventoExistente.setImg(imgString64);

            eventoService.guardarEvento(eventoExistente);
            return ResponseEntity.ok().body("{\"message\": \"Evento Editado exitosamente \"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar el archivo: " + e.getMessage());
        }
    }

    @DeleteMapping("/eliminar/{id}")
    public ResponseEntity<String> eliminarEvento(@PathVariable Long id) {
        try {
            eventoService.eliminarEventoPorId(id);
            return ResponseEntity.ok().body("{\"message\": \"Evento Eliminado exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al eliminar el evento: " + e.getMessage());
        }
    }

}

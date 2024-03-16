package com.gestion.encuesta.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.gestion.encuesta.model.Proyecto;
import com.gestion.encuesta.service.ProyectoService;

@RestController
@RequestMapping("/proyectos")
@CrossOrigin("*")
public class ProyectoController {
    @Autowired
    private ProyectoService proyectoService;

    @GetMapping("/listar")
    public List<Proyecto> listarProyectos() {
        return proyectoService.obtenerTodosLosProyectos();
    }
    
    @GetMapping("/listar/{id}")
    public Proyecto listarProyectoPorId(@PathVariable Long id) {
        return proyectoService.obtenerProyectoPorId(id);
    }

    @PostMapping(value = "/guardar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> guardarProyecto(@RequestParam("img") String imgString64,
                                             @RequestParam("titulo") String titulo,
                                             @RequestParam("descripcion") String descripcion,
                                             @RequestParam("ubicacion") String ubicacion,
                                             @RequestParam("estado") String estado) {
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

            if (ubicacion == null || ubicacion.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo ubicación es obligatorio");
            }

            if (estado == null || estado.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("El campo estado es obligatorio");
            }

            Proyecto proyecto = new Proyecto();
            proyecto.setTitulo(titulo);
            proyecto.setDescripcion(descripcion);
            proyecto.setUbicacion(ubicacion);
            proyecto.setEstado(estado);
            proyecto.setImg(imgString64);
            proyectoService.guardarProyecto(proyecto);

            return ResponseEntity.ok().body("{\"message\": \"Proyecto guardado exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }


    @PutMapping(value = "/editar/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> editarProyecto(@PathVariable Long id,
                                            @RequestParam("img") String imgString64,
                                            @RequestParam("titulo") String titulo,
                                            @RequestParam("descripcion") String descripcion,
                                            @RequestParam("ubicacion") String ubicacion,
                                            @RequestParam("estado") String estado) {
        try {
            Proyecto proyectoExistente = proyectoService.obtenerProyectoPorId(id);
            if (proyectoExistente == null) {
                return ResponseEntity.badRequest().body("El proyecto a editar no existe");
            }

            if (titulo == null || titulo.trim().isEmpty() ||
                    descripcion == null || descripcion.trim().isEmpty() ||
                    estado == null || estado.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Los campos Título, descripción y estado no pueden estar vacíos");
            }

            proyectoExistente.setTitulo(titulo);
            proyectoExistente.setDescripcion(descripcion);
            proyectoExistente.setUbicacion(ubicacion);
            proyectoExistente.setEstado(estado);
            proyectoExistente.setImg(imgString64);

            proyectoService.guardarProyecto(proyectoExistente);
            return ResponseEntity.ok().body("{\"message\": \"Proyecto editado exitosamente\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error al procesar la solicitud: " + e.getMessage());
        }
    }

    @DeleteMapping("/eliminar/{id}")
    public void eliminarProyecto(@PathVariable Long id) {
        proyectoService.eliminarProyectoPorId(id);
    }
}

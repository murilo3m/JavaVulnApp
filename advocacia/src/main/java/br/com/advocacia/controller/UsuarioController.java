package br.com.advocacia.controller;

import br.com.advocacia.entities.Usuario;
import br.com.advocacia.config.security.ErroDTO;
import br.com.advocacia.config.security.TokenUtil;
import br.com.advocacia.controller.DTOs.UsuarioDTO;
import br.com.advocacia.service.usuario.IUsuarioService;
import io.github.bucket4j.Bucket;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/usuario")
public class UsuarioController {

    @Autowired
    private Bucket bucket;

    public static final String USUARIONOTFOUND = "Usuário não encontrado!";
    final IUsuarioService usuarioService;
    final PasswordEncoder passwordEncoder;


    public UsuarioController(IUsuarioService usuarioService, PasswordEncoder passwordEncoder) {
        this.usuarioService = usuarioService;
        this.passwordEncoder = passwordEncoder;

    }


    @PostMapping("/login")
    public ResponseEntity<Object> realizarLogin(@RequestBody @Valid Usuario usuario) {

        if (bucket.tryConsume(1)) {
            Optional<Usuario> u = usuarioService.findByLogin(usuario.getLogin());
            if (u.isPresent() && usuarioService.verifyPassword(usuario.getSenha(), u.get())) {
                String token = new TokenUtil().encodeToken(u);
                return ResponseEntity.ok(
                        new UsuarioDTO(u.get().getId(), u.get().getLogin(), u.get().getNome(), u.get().getIsAdmin(), token));
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas!");
        }

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Limite de taxa excedido. Tente novamente mais tarde.");
    }

    @PostMapping()
    public ResponseEntity<Object> save(@RequestBody @Valid Usuario usuario) {
        if (usuarioService.existsByLogin(usuario.getLogin())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Login indisponível");
        }
        String passwordCripto = passwordEncoder.encode(usuario.getSenha());
        usuario.setSenha(passwordCripto);

        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.save(usuario));
    }

    @PutMapping()
    public ResponseEntity<Object> updatePassword(@RequestBody @Valid Usuario usuario) {
        Optional<Usuario> u = usuarioService.findByLogin(usuario.getLogin());
        if (u.isPresent()) {
            u.get().setSenha(passwordEncoder.encode(usuario.getSenha()));
            return ResponseEntity.status(HttpStatus.OK).body(usuarioService.save(u.get()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErroDTO(404, USUARIONOTFOUND));
        }
    }

    @GetMapping()
    public ResponseEntity<Object> findAllUsuario() {
        List<Usuario> usuarios = usuarioService.findAll();
        List<UsuarioDTO> usuarioDTOs = new ArrayList<>();
        for (Usuario usuario : usuarios) {
            UsuarioDTO usuarioDTO = new UsuarioDTO(usuario.getId(), usuario.getNome(), usuario.getLogin(), usuario.getIsAdmin());
            usuarioDTOs.add(usuarioDTO);
        }
        return ResponseEntity.status(HttpStatus.OK).body(usuarioDTOs);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Object> findUsuarioById(@PathVariable(value = "id") Long id, Authentication auth) {
        return usuarioService.findById(id)
                .filter(u -> u.getLogin().equals(auth.getPrincipal()))
                .<ResponseEntity<Object>>map(usuario -> ResponseEntity.status(HttpStatus.OK).body(usuario))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErroDTO(404, USUARIONOTFOUND)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Object> deleteUsuarioById(@PathVariable(value = "id") Long id, Authentication auth) {
        if (!"admin".equals(auth.getCredentials()))
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario não autorizado!");
        Optional<Usuario> usuarioOptional = usuarioService.findById(id);
        if (usuarioOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErroDTO(404, USUARIONOTFOUND));
        }
        usuarioService.deleteById(id);
        return ResponseEntity.status(HttpStatus.OK).body("Usuario deletado com sucesso!");
    }

}
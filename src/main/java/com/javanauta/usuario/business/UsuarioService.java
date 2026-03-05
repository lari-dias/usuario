package com.javanauta.usuario.business;

import com.javanauta.usuario.business.dto.UsuarioDTO;
import com.javanauta.usuario.infrastructure.entity.Usuario;
import com.javanauta.usuario.infrastructure.repository.UsuarioRepository;
import com.javanauta.usuario.infrastructure.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // Criar usuário
    public UsuarioDTO salvaUsuario(UsuarioDTO dto) {

        Usuario usuario = new Usuario();
        usuario.setNome(dto.getNome());
        usuario.setEmail(dto.getEmail());
        usuario.setSenha(passwordEncoder.encode(dto.getSenha()));

        usuarioRepository.save(usuario);

        return toDTO(usuario);
    }

    // Buscar usuário pelo email
    public Usuario buscarUsuarioPorEmail(String email) {
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
    }

    // Deletar usuário pelo email
    public void deletaUsuarioPorEmail(String email) {

        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        usuarioRepository.delete(usuario);
    }

    // Atualizar dados do usuário autenticado
    public UsuarioDTO atualizaDadosUsuario(String authorizationHeader,
                                           UsuarioDTO dto) {

        // Validar header Authorization
        if (authorizationHeader == null ||
                !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Token inválido");
        }

        // Remover prefixo Bearer
        String token = authorizationHeader.substring(7);

        // Obter email do JWT
        String emailToken = jwtUtil.extractUsername(token);

        // Buscar usuário no banco
        Usuario usuario = usuarioRepository.findByEmail(emailToken)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        // Atualizar apenas campos enviados
        if (dto.getNome() != null && !dto.getNome().isBlank()) {
            usuario.setNome(dto.getNome());
        }

        if (dto.getEmail() != null && !dto.getEmail().isBlank()) {
            usuario.setEmail(dto.getEmail());
        }

        if (dto.getSenha() != null && !dto.getSenha().isBlank()) {
            usuario.setSenha(passwordEncoder.encode(dto.getSenha()));
        }

        usuarioRepository.save(usuario);

        return toDTO(usuario);
    }

    // Converter Entity para DTO
    private UsuarioDTO toDTO(Usuario usuario) {

        UsuarioDTO dto = new UsuarioDTO();
        dto.setNome(usuario.getNome());
        dto.setEmail(usuario.getEmail());

        return dto;
    }
}

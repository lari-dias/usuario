package com.javanauta.usuario.business;

import com.javanauta.usuario.business.converter.UsuarioConverter;
import com.javanauta.usuario.business.dto.EnderecoDTO;
import com.javanauta.usuario.business.dto.TelefoneDTO;
import com.javanauta.usuario.business.dto.UsuarioDTO;
import com.javanauta.usuario.infrastructure.entity.Endereco;
import com.javanauta.usuario.infrastructure.entity.Telefone;
import com.javanauta.usuario.infrastructure.entity.Usuario;
import com.javanauta.usuario.infrastructure.exeptions.ResourceNotFoundExeption;
import com.javanauta.usuario.infrastructure.repository.EnderecoRepository;
import com.javanauta.usuario.infrastructure.repository.TelefoneRepository;
import com.javanauta.usuario.infrastructure.repository.UsuarioRepository;
import com.javanauta.usuario.infrastructure.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final UsuarioConverter usuarioConverter;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EnderecoRepository enderecoRepository;
    private final TelefoneRepository telefoneRepository;

    public UsuarioDTO salvaUsuario(UsuarioDTO usuarioDTO) {

        Usuario usuario = usuarioConverter.paraUsuario(usuarioDTO);

        usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));

        Usuario usuarioSalvo = usuarioRepository.save(usuario);

        return usuarioConverter.paraUsuarioDTO(usuarioSalvo);
    }

    @Transactional(readOnly = true)
    public UsuarioDTO buscarUsuarioPorEmail(String email) {

        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Email não encontrado: " + email));

        return usuarioConverter.paraUsuarioDTO(usuario);
    }

    public void deletaUsuarioPorEmail(String email) {
        usuarioRepository.deleteByEmail(email);
    }

    public UsuarioDTO atualizaDadosUsuario(String token, UsuarioDTO usuarioDTO) {

        String email = jwtUtil.extrairEmailToken(token.substring(7));

        if (usuarioDTO.getSenha() != null) {
            usuarioDTO.setSenha(passwordEncoder.encode(usuarioDTO.getSenha()));
        }

        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Email não localizado"));

        Usuario usuarioAtualizado = usuarioConverter.atualizarUsuario(usuarioDTO, usuario);

        return usuarioConverter.paraUsuarioDTO(
                usuarioRepository.save(usuarioAtualizado)
        );
    }

    public EnderecoDTO atualizaEndereco(Long idEndereco, EnderecoDTO enderecoDTO) {

        Endereco endereco = enderecoRepository.findById(idEndereco)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Id não encontrado: " + idEndereco));

        Endereco enderecoAtualizado = usuarioConverter.atualizarEndereco(
                enderecoDTO,
                endereco
        );

        return usuarioConverter.paraEnderecoDTO(
                enderecoRepository.save(enderecoAtualizado)
        );
    }

    public TelefoneDTO atualizaTelefone(Long idTelefone, TelefoneDTO telefoneDTO) {

        Telefone telefone = telefoneRepository.findById(idTelefone)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Id não encontrado: " + idTelefone));

        Telefone telefoneAtualizado = usuarioConverter.atualizarTelefone(
                telefoneDTO,
                telefone
        );

        return usuarioConverter.paraTelefoneDTO(
                telefoneRepository.save(telefoneAtualizado)
        );
    }
}
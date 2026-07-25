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

        // Criptografa a senha antes de salvar
        usuario.setSenha(passwordEncoder.encode(usuario.getSenha()));

        Usuario usuarioSalvo = usuarioRepository.save(usuario);

        return usuarioConverter.paraUsuarioDTO(usuarioSalvo);
    }

    @Transactional(readOnly = true)
    public UsuarioDTO buscarUsuarioPorEmail(String email) {

        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Email não encontrado " + email));

        return usuarioConverter.paraUsuarioDTO(usuario);
    }

    public void deletaUsuarioPorEmail(String email) {

        usuarioRepository.deleteByEmail(email);
    }

    public UsuarioDTO atualizaDadosUsuario(String token, UsuarioDTO dto) {

        String email = jwtUtil.extrairEmailToken(token.substring(7));

        dto.setSenha(
                dto.getSenha() != null
                        ? passwordEncoder.encode(dto.getSenha())
                        : null
        );

        Usuario usuarioEntity = usuarioRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Email não localizado"));

        Usuario usuario = usuarioConverter.updateDeUsuario(dto, usuarioEntity);

        return usuarioConverter.paraUsuarioDTO(
                usuarioRepository.save(usuario)
        );
    }

    public EnderecoDTO atualizaEndereco(Long idEndereco, EnderecoDTO enderecoDTO) {

        System.out.println("ID recebido: " + idEndereco);
        System.out.println("Numero recebido: " + enderecoDTO.getNumero());

        Endereco entity = enderecoRepository.findById(idEndereco)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Id não encontrado: " + idEndereco));

        System.out.println("Numero atual no banco: " + entity.getNumero());

        Endereco endereco = usuarioConverter.updateEndereco(enderecoDTO, entity);

        System.out.println("Numero após update: " + endereco.getNumero());

        Endereco salvo = enderecoRepository.save(endereco);

        System.out.println("Numero salvo no banco: " + salvo.getNumero());

        return usuarioConverter.paraEnderecoDTO(salvo);
    }

    public TelefoneDTO atualizaTelefone(Long idTelefone, TelefoneDTO dto) {

        Telefone entity = telefoneRepository.findById(idTelefone)
                .orElseThrow(() ->
                        new ResourceNotFoundExeption("Id não encontrado: " + idTelefone));

        Telefone telefone = usuarioConverter.updateTelefone(dto, entity);

        return usuarioConverter.paraTelefoneDTO(
                telefoneRepository.save(telefone)
        );
    }
}
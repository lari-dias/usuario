package com.javanauta.usuario.business.converter;

import com.javanauta.usuario.business.dto.EnderecoDTO;
import com.javanauta.usuario.business.dto.TelefoneDTO;
import com.javanauta.usuario.business.dto.UsuarioDTO;
import com.javanauta.usuario.infrastructure.entity.Endereco;
import com.javanauta.usuario.infrastructure.entity.Telefone;
import com.javanauta.usuario.infrastructure.entity.Usuario;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class UsuarioConverter {

    public Usuario paraUsuario(UsuarioDTO usuarioDTO) {
        return Usuario.builder()
                .nome(usuarioDTO.getNome())
                .email(usuarioDTO.getEmail())
                .senha(usuarioDTO.getSenha())
                .enderecos(paraListaEnderecos(usuarioDTO.getEnderecos()))
                .telefones(paraListaTelefones(usuarioDTO.getTelefones()))
                .build();
    }

    public Endereco paraEndereco(EnderecoDTO enderecoDTO) {
        return Endereco.builder()
                .rua(enderecoDTO.getRua())
                .numero(enderecoDTO.getNumero())
                .complemento(enderecoDTO.getComplemento())
                .cidade(enderecoDTO.getCidade())
                .estado(enderecoDTO.getEstado())
                .cep(enderecoDTO.getCep())
                .build();
    }

    public Telefone paraTelefone(TelefoneDTO telefoneDTO) {
        return Telefone.builder()
                .ddd(telefoneDTO.getDdd())
                .numero(telefoneDTO.getNumero())
                .build();
    }

    public List<Endereco> paraListaEnderecos(List<EnderecoDTO> enderecosDTO) {
        if (enderecosDTO == null) {
            return List.of();
        }

        return enderecosDTO.stream()
                .map(this::paraEndereco)
                .toList();
    }

    public List<Telefone> paraListaTelefones(List<TelefoneDTO> telefonesDTO) {
        if (telefonesDTO == null) {
            return List.of();
        }

        return telefonesDTO.stream()
                .map(this::paraTelefone)
                .toList();
    }

    public UsuarioDTO paraUsuarioDTO(Usuario usuario) {
        return UsuarioDTO.builder()
                .nome(usuario.getNome())
                .email(usuario.getEmail())
                .senha(usuario.getSenha())
                .enderecos(paraListaEnderecosDTO(usuario.getEnderecos()))
                .telefones(paraListaTelefonesDTO(usuario.getTelefones()))
                .build();
    }

    public EnderecoDTO paraEnderecoDTO(Endereco endereco) {
        return EnderecoDTO.builder()
                .id(endereco.getId())
                .rua(endereco.getRua())
                .numero(endereco.getNumero())
                .complemento(endereco.getComplemento())
                .cidade(endereco.getCidade())
                .estado(endereco.getEstado())
                .cep(endereco.getCep())
                .build();
    }

    public TelefoneDTO paraTelefoneDTO(Telefone telefone) {
        return TelefoneDTO.builder()
                .id(telefone.getId())
                .ddd(telefone.getDdd())
                .numero(telefone.getNumero())
                .build();
    }

    public List<EnderecoDTO> paraListaEnderecosDTO(List<Endereco> enderecos) {
        if (enderecos == null) {
            return List.of();
        }

        return enderecos.stream()
                .map(this::paraEnderecoDTO)
                .toList();
    }

    public List<TelefoneDTO> paraListaTelefonesDTO(List<Telefone> telefones) {
        if (telefones == null) {
            return List.of();
        }

        return telefones.stream()
                .map(this::paraTelefoneDTO)
                .toList();
    }

    public Usuario atualizarUsuario(UsuarioDTO usuarioDTO, Usuario usuario) {
        return Usuario.builder()
                .id(usuario.getId())
                .nome(valorOuAtual(usuarioDTO.getNome(), usuario.getNome()))
                .email(valorOuAtual(usuarioDTO.getEmail(), usuario.getEmail()))
                .senha(valorOuAtual(usuarioDTO.getSenha(), usuario.getSenha()))
                .enderecos(usuario.getEnderecos())
                .telefones(usuario.getTelefones())
                .build();
    }

    public Endereco atualizarEndereco(EnderecoDTO enderecoDTO, Endereco endereco) {
        return Endereco.builder()
                .id(endereco.getId())
                .rua(valorOuAtual(enderecoDTO.getRua(), endereco.getRua()))
                .numero(valorOuAtual(enderecoDTO.getNumero(), endereco.getNumero()))
                .complemento(valorOuAtual(enderecoDTO.getComplemento(), endereco.getComplemento()))
                .cidade(valorOuAtual(enderecoDTO.getCidade(), endereco.getCidade()))
                .estado(valorOuAtual(enderecoDTO.getEstado(), endereco.getEstado()))
                .cep(valorOuAtual(enderecoDTO.getCep(), endereco.getCep()))
                .build();
    }

    public Telefone atualizarTelefone(TelefoneDTO telefoneDTO, Telefone telefone) {
        return Telefone.builder()
                .id(telefone.getId())
                .ddd(valorOuAtual(telefoneDTO.getDdd(), telefone.getDdd()))
                .numero(valorOuAtual(telefoneDTO.getNumero(), telefone.getNumero()))
                .build();
    }

    private <T> T valorOuAtual(T novoValor, T valorAtual) {
        return novoValor != null ? novoValor : valorAtual;
    }
}
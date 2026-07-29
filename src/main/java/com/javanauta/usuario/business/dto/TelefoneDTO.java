package com.javanauta.usuario.business.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TelefoneDTO {

    private Long id;
    private String numero;
    private String ddd;
}
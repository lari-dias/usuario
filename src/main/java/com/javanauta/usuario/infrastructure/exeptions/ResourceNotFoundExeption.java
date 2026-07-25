package com.javanauta.usuario.infrastructure.exeptions;

public class ResourceNotFoundExeption extends RuntimeException {

    public ResourceNotFoundExeption(String mensagem) {
        super(mensagem);

    }
    public ResourceNotFoundExeption(String mensagem, Throwable throwable){
        super(mensagem, throwable);
    }
}

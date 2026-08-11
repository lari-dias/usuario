# API Usuário

API REST desenvolvida em **Java com Spring Boot** para gerenciamento de usuários, endereços e telefones. O projeto possui autenticação utilizando **JWT**, persistência de dados com **PostgreSQL** e segue uma arquitetura organizada em camadas.

## 🚀 Tecnologias utilizadas

* Java 17
* Spring Boot
* Spring Web
* Spring Data JPA
* Spring Security
* JWT (JSON Web Token)
* PostgreSQL
* Lombok
* Docker

## 📌 Funcionalidades

* Cadastro de usuários
* Login com autenticação JWT
* Consulta de usuário por e-mail
* Atualização de dados do usuário
* Atualização de endereço
* Atualização de telefone
* Exclusão de usuário
* Proteção de endpoints com Spring Security

## 🏗️ Estrutura do projeto

```
src/main/java/com/javanauta/usuario

├── controller
│   └── Endpoints da API
│
├── business
│   ├── Services
│   ├── DTOs
│   └── Converters
│
└── infrastructure
    ├── Entities
    ├── Repositories
    └── Security
```

## 🔐 Autenticação

A API utiliza autenticação baseada em JWT.

Fluxo:

1. Usuário realiza login através do endpoint:

```
POST /usuario/login
```

2. A API retorna um token JWT.

3. O token deve ser enviado nas próximas requisições protegidas:

```
Authorization: Bearer TOKEN
```

## 📍 Endpoints

### Criar usuário

```
POST /usuario
```

Exemplo:

```json
{
  "nome": "Carlos Eduardo Mendes",
  "email": "carlos.mendes@email.com",
  "senha": "456789"
}
```

---

### Login

```
POST /usuario/login
```

Body:

```json
{
  "email": "carlos.mendes@email.com",
  "senha": "456789"
}
```

---

### Buscar usuário

```
GET /usuario?email=email@email.com
```

Necessário JWT.

---

### Atualizar usuário

```
PUT /usuario
```

Necessário JWT.

---

### Atualizar endereço

```
PUT /usuario/endereco?id={id}
```

---

### Atualizar telefone

```
PUT /usuario/telefone?id={id}
```

---

### Deletar usuário

```
DELETE /usuario/{email}
```

Necessário JWT.

## ⚙️ Como executar o projeto

### Pré-requisitos

* Java 17+
* PostgreSQL
* Gradle

### Configuração do banco

No arquivo:

```
application.properties
```

configure:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/db_usuario
spring.datasource.username=postgres
spring.datasource.password=SUA_SENHA
```

### Executar aplicação

Linux/Mac:

```bash
./gradlew bootRun
```

Windows:

```bash
gradlew bootRun
```

A API será iniciada em:

```
http://localhost:8081
```

## 🐳 Docker

Para criar a imagem:

```bash
docker build -t usuario .
```

Executar o container:

```bash
docker run -p 8081:8081 usuario
```

## 👩‍💻 Desenvolvimento

Projeto desenvolvido para estudo e prática de:

* Desenvolvimento de APIs REST
* Arquitetura em camadas
* Segurança com JWT
* Integração entre serviços
* Boas práticas no desenvolvimento backend com Java

## 📄 Licença

Este projeto está sob licença MIT.

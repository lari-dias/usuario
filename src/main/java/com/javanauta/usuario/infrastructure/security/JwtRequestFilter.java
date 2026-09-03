package com.javanauta.usuario.infrastructure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JwtRequestFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        System.out.println("========================================");
        System.out.println("URI: " + request.getRequestURI());
        System.out.println("Método: " + request.getMethod());

        String header = request.getHeader("Authorization");
        System.out.println("Authorization: " + header);

        String token = null;
        String username = null;

        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
            System.out.println("Token recebido.");

            try {
                username = jwtUtil.extrairEmailToken(token);
                System.out.println("Email extraído do token: " + username);
            } catch (Exception e) {
                System.out.println("Erro ao ler token:");
                e.printStackTrace();

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } else {
            System.out.println("Header Authorization não encontrado ou inválido.");
        }

        if (username != null &&
                SecurityContextHolder.getContext().getAuthentication() == null) {

            try {

                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                System.out.println("Usuário encontrado: " + userDetails.getUsername());

                boolean tokenValido =
                        jwtUtil.validateToken(token, userDetails.getUsername());

                System.out.println("Token válido: " + tokenValido);

                if (tokenValido) {

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication);

                    System.out.println("Usuário autenticado com sucesso.");

                } else {

                    System.out.println("Token inválido.");

                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }

            } catch (Exception e) {

                System.out.println("Erro ao carregar usuário:");
                e.printStackTrace();

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        System.out.println("Authentication final: "
                + SecurityContextHolder.getContext().getAuthentication());

        System.out.println("Continuando para o Controller...");
        System.out.println("========================================");

        filterChain.doFilter(request, response);
    }
}
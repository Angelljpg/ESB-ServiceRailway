package com.utd.ti.soa.esb_service.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import com.utd.ti.soa.esb_service.model.User;
import com.utd.ti.soa.esb_service.utils.Auth;

@RestController
@RequestMapping("/api/v1/esb")
public class ESBUserController {

    private final WebClient webClient;
    private final Auth auth;

    public ESBUserController(
            @Value("${USER_SERVICE_URL:https://usersrailway-definitive.up.railway.app}") String userServiceUrl,
            @Value("${USER_SERVICE_PORT:3010}") String userServicePort,
            Auth auth) {
        
        this.auth = auth;
        String baseUrl = userServiceUrl + ":" + userServicePort + "/api/users";
        
        this.webClient = WebClient.builder()
            .baseUrl(baseUrl)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, "application/json")
            .defaultHeader(HttpHeaders.ACCEPT, "application/json")
            .build();
    }

    @PostMapping("/user")
    public ResponseEntity<?> createUser(@RequestBody User user, 
                                      @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            System.out.println("Request Body: " + user);
            System.out.println("Token recibido: " + token);

            if (!auth.validateToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
            }
            
            String userType = auth.getUserType(token);
            if (userType == null || !(userType.equals("admin") || userType.equals("client") || userType.equals("provider"))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
            }

            String response = webClient.post()
                    .uri("/create")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(user)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return ResponseEntity.ok(response);
        } catch (WebClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error interno del servidor: " + e.getMessage());
        }
    }

    @PostMapping("/user/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            System.out.println("Request Body: " + user);

            String response = webClient.post()
                    .uri("/login")
                    .bodyValue(user)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            if (response.contains("Usuario autenticado")) {
                return ResponseEntity.ok(response);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales incorrectas");
        } catch (WebClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error interno del servidor: " + e.getMessage());
        }
    }

    @GetMapping("/user/all")
    public ResponseEntity<?> getAllUsers(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            System.out.println("Token recibido: " + token);

            if (!auth.validateToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
            }

            String response = webClient.get()
                    .uri("/")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return ResponseEntity.ok(response);
        } catch (WebClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error interno del servidor: " + e.getMessage());
        }
    }

    @PatchMapping("/user/{id}")
    public ResponseEntity<?> updateUser(@PathVariable String id, 
                                      @RequestBody User user, 
                                      @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            System.out.println("Request Body: " + user);
            System.out.println("Token recibido: " + token);

            if (!auth.validateToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
            }

            String response = webClient.patch()
                    .uri("/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(user)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return ResponseEntity.ok(response);
        } catch (WebClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error interno del servidor: " + e.getMessage());
        }
    }

    @PatchMapping("/user/delete/{id}")
    public ResponseEntity<?> deactivateUser(@PathVariable String id, 
                                          @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            System.out.println("Token recibido: " + token);

            if (!auth.validateToken(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
            }

            String response = webClient.patch()
                    .uri("/delete/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            return ResponseEntity.ok(response);
        } catch (WebClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error interno del servidor: " + e.getMessage());
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("ESB Service is running");
    }
}
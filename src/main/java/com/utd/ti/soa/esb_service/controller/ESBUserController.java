package com.utd.ti.soa.esb_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import com.utd.ti.soa.esb_service.model.User;
import com.utd.ti.soa.esb_service.utils.Auth;
import reactor.core.publisher.Mono;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/esb")
public class ESBUserController {

    private final WebClient webClient;
    private final Auth auth;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public ESBUserController() {
        this.webClient = WebClient.builder()
            .baseUrl("https://usersrailway-production.up.railway.app")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @PostMapping("/user")
    public ResponseEntity<String> createUser(@RequestBody User user, 
                                           @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando usuario: {}", user.getUsername());
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido recibido");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        String userType = auth.getUserType(token);
        if (userType == null || !(userType.equals("admin") || userType.equals("client") || userType.equals("provider"))) {
            log.warn("Intento de acceso no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }

        return executeWithRetry(
            () -> webClient.post()
                .uri("/api/users/create")
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(user),
            MAX_RETRIES
        );
    }

    @PostMapping("/user/login")
    public ResponseEntity<String> login(@RequestBody User user) {
        log.info("Intento de login para usuario: {}", user.getUsername());
        
        return executeWithRetry(
            () -> webClient.post()
                .uri("/api/users/login")
                .bodyValue(user),
            MAX_RETRIES
        );
    }

    @GetMapping("/user/all")
    public ResponseEntity<String> getAllUsers(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando todos los usuarios");
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para listar usuarios");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }
        
        return executeWithRetry(
            () -> webClient.get()
                .uri("/api/users/")
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @PatchMapping("/user/{id}")
    public ResponseEntity<String> updateUser(@PathVariable String id, 
                                           @RequestBody User user,
                                           @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando usuario ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para actualización");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }
        
        return executeWithRetry(
            () -> webClient.patch()
                .uri("/api/users/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(user),
            MAX_RETRIES
        );
    }

    @DeleteMapping("/user/delete/{id}")
    public ResponseEntity<String> deactivateUser(@PathVariable String id,
                                               @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Eliminando usuario ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para eliminación");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        return executeWithRetry(
            () -> webClient.delete()
                .uri("/api/users/delete/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    /**
     * Método genérico para ejecutar peticiones con reintentos
     */
    private ResponseEntity<String> executeWithRetry(Supplier<WebClient.RequestHeadersSpec<?>> requestSupplier, 
                                                int maxRetries) {
        // Usamos un array para poder modificar el valor dentro de la lambda
        final int[] attemptCount = {0};
        
        while (true) {
            attemptCount[0]++;
            try {
                String response = requestSupplier.get()
                    .retrieve()
                    .onStatus(HttpStatus::is5xxServerError, clientResponse -> {
                        if (clientResponse.statusCode() == HttpStatus.BAD_GATEWAY && attemptCount[0] < maxRetries) {
                            log.warn("Intento {} - Error 502, reintentando...", attemptCount[0]);
                            return Mono.empty();
                        }
                        return clientResponse.bodyToMono(String.class)
                            .flatMap(errorBody -> Mono.error(new WebClientResponseException(
                                clientResponse.statusCode().value(),
                                "Error del servicio",
                                clientResponse.headers().asHttpHeaders(),
                                errorBody.getBytes(),
                                null)));
                    })
                    .bodyToMono(String.class)
                    .block();

                log.info("Petición exitosa después de {} intentos", attemptCount[0]);
                return ResponseEntity.ok(response);

            } catch (WebClientResponseException e) {
                if (e.getStatusCode() != HttpStatus.BAD_GATEWAY || attemptCount[0] >= maxRetries) {
                    log.error("Error del cliente HTTP: {}", e.getStatusCode());
                    return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
                }
                // Espera antes de reintentar (backoff exponencial)
                try {
                    Thread.sleep(RETRY_DELAY_MS * (long) Math.pow(2, attemptCount[0] - 1));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error durante el reintento");
                }
            } catch (Exception e) {
                log.error("Error inesperado", e);
                return ResponseEntity.internalServerError().body("Error interno del servidor");
            }
        }
    }
}
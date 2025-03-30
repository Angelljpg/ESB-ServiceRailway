package com.utd.ti.soa.esb_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import com.utd.ti.soa.esb_service.model.Client;
import com.utd.ti.soa.esb_service.utils.Auth;
import reactor.core.publisher.Mono;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/esb")
public class ESBClientController {

    private final WebClient webClient;
    private final Auth auth;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public ESBClientController() {
        this.webClient = WebClient.builder()
            .baseUrl("http://clientsrailway.railway.internal:3011")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @GetMapping("/client")
    public ResponseEntity<String> getClients(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando todos los clientes");
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para listar clientes");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }

        String userType = auth.getUserType(token);
        if (userType == null) {
            log.warn("Intento de acceso sin tipo de usuario");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }

        return executeWithRetry(
            () -> webClient.get()
                .uri("/api/clients/")
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @PostMapping("/client/create")
    public ResponseEntity<String> createClient(@RequestBody Client client, 
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando cliente: {}", client.getName());
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para creación de cliente");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }

        return executeWithRetry(
            () -> webClient.post()
                .uri("/api/clients/create")
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(client),
            MAX_RETRIES
        );
    }

    @PutMapping("/client/{id}")
    public ResponseEntity<String> updateClient(@PathVariable String id, 
                                             @RequestBody Client client,
                                             @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando cliente ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para actualización de cliente");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }

        String userType = auth.getUserType(token);
        if (userType == null || !(userType.equals("admin") || userType.equals("cliente") || userType.equals("proveedor"))) {
            log.warn("Intento de acceso no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }

        return executeWithRetry(
            () -> webClient.put()
                .uri("/api/clients/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(client),
            MAX_RETRIES
        );
    }

    @PatchMapping("/client/delete/{id}")
    public ResponseEntity<String> deactivateClient(@PathVariable String id,
                                                @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Desactivando cliente ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para desactivación de cliente");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Invalido");
        }

        String userType = auth.getUserType(token);
        if (userType == null || !userType.equals("admin")) {
            log.warn("Intento de desactivación no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }

        return executeWithRetry(
            () -> webClient.patch()
                .uri("/api/clients/delete/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    /**
     * Método genérico para ejecutar peticiones con reintentos
     * (Igual al implementado en ESBUserController)
     */
    private ResponseEntity<String> executeWithRetry(Supplier<WebClient.RequestHeadersSpec<?>> requestSupplier, 
                                                int maxRetries) {
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
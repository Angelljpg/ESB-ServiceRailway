package com.utd.ti.soa.esb_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import com.utd.ti.soa.esb_service.model.Product;
import com.utd.ti.soa.esb_service.utils.Auth;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/esb")
public class ESBProductController {

    private final WebClient webClient;
    private final Auth auth;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public ESBProductController() {
        this.webClient = WebClient.builder()
            .baseUrl("https://productsrailway-production.up.railway.app/api/products")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @GetMapping("/products")
    public ResponseEntity<String> getAllProducts(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando todos los productos");
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para listar productos");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        String userType = auth.getUserType(token);
        if (userType == null || !(userType.equals("admin") || userType.equals("client") || userType.equals("provider"))) {
            log.warn("Intento de acceso no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }

        return executeWithRetry(
            () -> webClient.get()
                .uri("/")
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @PostMapping("/products/create")
    public ResponseEntity<String> createProduct(@RequestBody Map<String, Object> productData, 
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        try {
            log.info("Creando producto con datos: {}", productData);
            
            // Validación de token y rol
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para creación de producto");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
            }
            
            String userType = auth.getUserType(token);
            if (userType == null || !userType.equals("admin")) {
                log.warn("Intento de creación de producto no autorizado con tipo: {}", userType);
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Solo administradores pueden crear productos");
            }

            // Construir el cuerpo manualmente
            Map<String, Object> requestBody = new LinkedHashMap<>();
            requestBody.put("ProductName", productData.get("ProductName"));
            requestBody.put("UnitPrice", productData.get("UnitPrice"));
            requestBody.put("Stock", productData.get("Stock"));
            requestBody.put("CategoryID", productData.get("CategoryID"));

            log.debug("Cuerpo final a enviar: {}", requestBody);

            return executeWithRetry(
                () -> webClient.post()
                    .uri("/create")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .acceptCharset(StandardCharsets.UTF_8)
                    .bodyValue(requestBody),
                MAX_RETRIES
            );
        } catch (Exception e) {
            log.error("Error inesperado al procesar la solicitud", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error interno al procesar la solicitud");
        }
}

    @PatchMapping("/products/update/{id}")
    public ResponseEntity<String> updateProduct(@PathVariable String id, 
                                              @RequestBody Product product,
                                              @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando producto ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para actualización de producto");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        String userType = auth.getUserType(token);
        if (userType == null || !userType.equals("admin")) {
            log.warn("Intento de actualización de producto no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Solo administradores pueden actualizar productos");
        }

        return executeWithRetry(
            () -> webClient.patch()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(product),
            MAX_RETRIES
        );
    }

    @DeleteMapping("/products/delete/{id}")
    public ResponseEntity<String> deleteProduct(@PathVariable String id,
                                              @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Eliminando producto ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para eliminación de producto");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        String userType = auth.getUserType(token);
        if (userType == null || !userType.equals("admin")) {
            log.warn("Intento de eliminación de producto no autorizado con tipo: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Solo administradores pueden eliminar productos");
        }

        return executeWithRetry(
            () -> webClient.delete()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    /**
     * Método genérico para ejecutar peticiones con reintentos
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
                    .onStatus(HttpStatus::is4xxClientError, clientResponse -> {
                        return clientResponse.bodyToMono(String.class)
                            .flatMap(errorBody -> Mono.error(new WebClientResponseException(
                                clientResponse.statusCode().value(),
                                "Error del cliente",
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
                    log.error("Error del cliente HTTP ({}): {}", e.getStatusCode(), e.getResponseBodyAsString());
                    
                    // Manejar específicamente errores 400 con más detalle
                    if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                        return ResponseEntity.status(e.getStatusCode())
                            .body("Error en la solicitud: " + e.getResponseBodyAsString());
                    }
                    
                    return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
                }
                
                // Espera antes de reintentar (backoff exponencial)
                try {
                    long delay = RETRY_DELAY_MS * (long) Math.pow(2, attemptCount[0] - 1);
                    log.warn("Reintentando en {} ms...", delay);
                    Thread.sleep(delay);
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
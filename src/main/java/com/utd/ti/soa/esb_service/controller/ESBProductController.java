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

import java.util.Map;
import java.util.HashMap;
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
    public ResponseEntity<Map<String, Object>> getAllProducts(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando todos los productos");
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para listar productos");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            // Todos los roles pueden ver productos
            String userType = auth.getUserType(token);
            if (userType == null || !(userType.equals("admin") || userType.equals("client") || userType.equals("provider"))) {
                log.warn("Tipo de usuario no válido: {}", userType);
                return buildErrorResponse(HttpStatus.FORBIDDEN, "Tipo de usuario no válido", "AUTH002");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.get()
                    .uri("/")
                    .header(HttpHeaders.AUTHORIZATION, token),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al obtener productos: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al recuperar productos", "SRV001");
        }
    }

    @PostMapping("/products/create")
    public ResponseEntity<Map<String, Object>> createProduct(
            @RequestBody Map<String, Object> productRequest,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando nuevo producto");
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para creación de producto");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            // Solo admin y provider pueden crear productos
            if (!userType.equals("admin") && !userType.equals("provider")) {
                log.warn("Intento de creación no autorizado por tipo: {}", userType);
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "No tiene permisos para crear productos", "AUTH003");
            }

            // Validación de campos obligatorios
            if (productRequest.get("ProductName") == null || 
                productRequest.get("UnitPrice") == null ||
                productRequest.get("Stock") == null ||
                productRequest.get("CategoryID") == null) {
                return buildErrorResponse(HttpStatus.BAD_REQUEST, 
                    "Faltan campos obligatorios", "VAL001");
            }

            // Validación de tipos de datos
            try {
                Double.parseDouble(productRequest.get("UnitPrice").toString());
                Integer.parseInt(productRequest.get("Stock").toString());
            } catch (NumberFormatException e) {
                return buildErrorResponse(HttpStatus.BAD_REQUEST, 
                    "Precio o Stock con formato inválido", "VAL002");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.post()
                    .uri("/create")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(productRequest),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al crear producto: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al crear producto", "SRV002");
        }
    }

    @PatchMapping("/products/update/{id}")
    public ResponseEntity<Map<String, Object>> updateProduct(
            @PathVariable String id,
            @RequestBody Product product,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando producto ID: {}", id);
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para actualización de producto");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            // Solo admin y provider pueden actualizar productos
            if (!userType.equals("admin") && !userType.equals("provider")) {
                log.warn("Intento de actualización no autorizado por tipo: {}", userType);
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "No tiene permisos para actualizar productos", "AUTH004");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.patch()
                    .uri("/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(product),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al actualizar producto: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al actualizar producto", "SRV003");
        }
    }

    @DeleteMapping("/products/delete/{id}")
    public ResponseEntity<Map<String, Object>> deleteProduct(
            @PathVariable String id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Eliminando producto ID: {}", id);
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para eliminación de producto");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            // Solo admin puede eliminar productos
            if (!auth.getUserType(token).equals("admin")) {
                log.warn("Intento de eliminación no autorizado");
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo administradores pueden eliminar productos", "AUTH005");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.delete()
                    .uri("/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al eliminar producto: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al eliminar producto", "SRV004");
        }
    }

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

    private Map<String, Object> buildSuccessResponse(String data) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("data", data);
        return response;
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status, String message, String code) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("success", false);
        errorResponse.put("error", message);
        errorResponse.put("code", code);
        
        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            errorResponse.put("errorDetails", "Consulte con el administrador del sistema");
        }
        
        return ResponseEntity.status(status).body(errorResponse);
    }
}
package com.utd.ti.soa.esb_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import com.utd.ti.soa.esb_service.utils.Auth;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/esb/orders") 
public class ESBOrderController {

    private final WebClient webClient;
    private final Auth auth;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public ESBOrderController() {
        this.webClient = WebClient.builder()
            .baseUrl("https://ordersrailway-production.up.railway.app/api/orders")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @PostMapping
    public ResponseEntity<String> createOrder(@RequestBody Map<String, Object> orderRequest,
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando nueva orden");
        
        // Validación mejorada del token
        ResponseEntity<String> tokenValidation = validateTokenAndRole(token, "admin|client");
        if (tokenValidation != null) return tokenValidation;
        
        // Validación de campos mejorada
        String[] requiredFields = {"ClientID", "ProductID", "PurchasedQuantity", 
                                 "DeliveryAddress", "ContactMethod", "PaymentMethod"};
        ResponseEntity<String> fieldValidation = validateRequiredFields(orderRequest, requiredFields);
        if (fieldValidation != null) return fieldValidation;

        // Validación de método de pago
        if (!validatePaymentMethod(orderRequest.get("PaymentMethod").toString())) {
            return ResponseEntity.badRequest().body("Método de pago inválido. Use: CASH, DEBIT_CARD o CREDIT_CARD");
        }

        return executeWithRetry(
            () -> webClient.post()
                .uri("/create")
                .header(HttpHeaders.AUTHORIZATION, token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(orderRequest),
            MAX_RETRIES
        );
    }

    @GetMapping
    public ResponseEntity<String> getAllOrders(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Obteniendo todas las órdenes");
        
        ResponseEntity<String> tokenValidation = validateTokenAndRole(token, "admin|client|provider");
        if (tokenValidation != null) return tokenValidation;
        
        return executeWithRetry(
            () -> webClient.get()
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<String> getOrderById(@PathVariable String id,
                                             @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Obteniendo orden con ID: {}", id);
        
        ResponseEntity<String> tokenValidation = validateTokenAndRole(token, "admin|client");
        if (tokenValidation != null) return tokenValidation;
        
        return executeWithRetry(
            () -> webClient.get()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @PutMapping("/{id}")
    public ResponseEntity<String> updateOrder(@PathVariable String id,
                                            @RequestBody Map<String, Object> orderUpdates,
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando orden con ID: {}", id);
        
        ResponseEntity<String> tokenValidation = validateTokenAndRole(token, "admin");
        if (tokenValidation != null) return tokenValidation;
        
        if (orderUpdates.get("PaymentMethod") != null && 
            !validatePaymentMethod(orderUpdates.get("PaymentMethod").toString())) {
            return ResponseEntity.badRequest().body("Método de pago inválido");
        }

        return executeWithRetry(
            () -> webClient.put()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(orderUpdates),
            MAX_RETRIES
        );
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deactivateOrder(@PathVariable String id,
                                                @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Desactivando orden con ID: {}", id);
        
        ResponseEntity<String> tokenValidation = validateTokenAndRole(token, "admin");
        if (tokenValidation != null) return tokenValidation;
        
        return executeWithRetry(
            () -> webClient.delete()
                .uri("/delete/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    // Métodos auxiliares mejorados
    private ResponseEntity<String> validateTokenAndRole(String token, String allowedRoles) {
        if (!auth.validateToken(token)) {
            log.warn("Token inválido");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        String userType = auth.getUserType(token);
        if (userType == null || !userType.matches(allowedRoles)) {
            log.warn("Acceso no autorizado para tipo de usuario: {}", userType);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado");
        }
        return null;
    }

    private ResponseEntity<String> validateRequiredFields(Map<String, Object> request, String[] fields) {
        for (String field : fields) {
            if (request.get(field) == null) {
                log.warn("Campo obligatorio faltante: {}", field);
                return ResponseEntity.badRequest()
                    .body(String.format("Campo obligatorio faltante: %s", field));
            }
        }
        return null;
    }

    private boolean validatePaymentMethod(String method) {
        return method != null && 
               (method.equals("CASH") || 
                method.equals("DEBIT_CARD") || 
                method.equals("CREDIT_CARD"));
    }

    private ResponseEntity<String> executeWithRetry(Supplier<WebClient.RequestHeadersSpec<?>> requestSupplier, 
                                                 int maxRetries) {
        final int[] attemptCount = {0};
        
        while (true) {
            attemptCount[0]++;
            try {
                String response = requestSupplier.get()
                    .retrieve()
                    .onStatus(HttpStatus::isError, clientResponse -> {
                        if (clientResponse.statusCode() == HttpStatus.BAD_GATEWAY && attemptCount[0] < maxRetries) {
                            log.warn("Intento {} - Error {}, reintentando...", 
                                    attemptCount[0], clientResponse.statusCode());
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
                log.error("Error en la respuesta: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
                if (attemptCount[0] >= maxRetries || 
                    e.getStatusCode() != HttpStatus.BAD_GATEWAY) {
                    return ResponseEntity.status(e.getStatusCode())
                        .body(e.getResponseBodyAsString());
                }
                
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
                return ResponseEntity.internalServerError()
                    .body("Error interno del servidor: " + e.getMessage());
            }
        }
    }
}
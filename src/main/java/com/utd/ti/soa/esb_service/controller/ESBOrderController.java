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
            .baseUrl("https://orders-service-production.up.railway.app/api/orders")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @PostMapping("/create")
    public ResponseEntity<String> createOrder(@RequestBody Map<String, Object> orderRequest,
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando nueva orden");
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para creación de orden");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        // Validar campos obligatorios
        if (orderRequest.get("ClientID") == null || 
            orderRequest.get("ProductID") == null ||
            orderRequest.get("PurchasedQuantity") == null ||
            orderRequest.get("DeliveryAddress") == null ||
            orderRequest.get("ContactMethod") == null ||
            orderRequest.get("PaymentMethod") == null) {
            return ResponseEntity.badRequest().body("Faltan campos obligatorios");
        }

        // Validar método de pago
        String paymentMethod = orderRequest.get("PaymentMethod").toString();
        if (!paymentMethod.equals("CASH") && !paymentMethod.equals("DEBIT_CARD") && !paymentMethod.equals("CREDIT_CARD")) {
            return ResponseEntity.badRequest().body("Método de pago inválido");
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

    @GetMapping("/")
    public ResponseEntity<String> getAllOrders(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Obteniendo todas las órdenes");
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para listar órdenes");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        return executeWithRetry(
            () -> webClient.get()
                .uri("/")
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<String> getOrderById(@PathVariable String id,
                                             @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Obteniendo orden con ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para obtener orden");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        return executeWithRetry(
            () -> webClient.get()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token),
            MAX_RETRIES
        );
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<String> updateOrder(@PathVariable String id,
                                            @RequestBody Map<String, Object> orderUpdates,
                                            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando orden con ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para actualizar orden");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        // Validar método de pago si está presente
        if (orderUpdates.get("PaymentMethod") != null) {
            String paymentMethod = orderUpdates.get("PaymentMethod").toString();
            if (!paymentMethod.equals("CASH") && !paymentMethod.equals("DEBIT_CARD") && !paymentMethod.equals("CREDIT_CARD")) {
                return ResponseEntity.badRequest().body("Método de pago inválido");
            }
        }

        return executeWithRetry(
            () -> webClient.put()
                .uri("/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, token)
                .bodyValue(orderUpdates),
            MAX_RETRIES
        );
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> deactivateOrder(@PathVariable String id,
                                                @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Desactivando orden con ID: {}", id);
        
        if (!auth.validateToken(token)) {
            log.warn("Token inválido para desactivar orden");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token Inválido");
        }
        
        return executeWithRetry(
            () -> webClient.delete()
                .uri("/delete/{id}", id)
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
                    
                    if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                        return ResponseEntity.status(e.getStatusCode())
                            .body("Error en la solicitud: " + e.getResponseBodyAsString());
                    }
                    
                    return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
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
                return ResponseEntity.internalServerError().body("Error interno del servidor");
            }
        }
    }
}
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
import java.util.Map;
import java.util.HashMap;
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
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody User user, @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Creando usuario: {}", user.getUsername());
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido recibido");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            String requestingUserId = auth.getUserId(token);
            
            if (userType == null || !(userType.equals("admin") || userType.equals("client") || userType.equals("provider"))) {
                log.warn("Tipo de usuario no válido: {}", userType);
                return buildErrorResponse(HttpStatus.FORBIDDEN, "Tipo de usuario no válido", "AUTH003");
            }

            // Clients and providers can only create their own user
            if ((userType.equals("client") || userType.equals("provider"))) {
                // Assuming User class has getUsername() instead of getId()
                if (!user.getUsername().equals(requestingUserId)) {
                    return buildErrorResponse(HttpStatus.FORBIDDEN, 
                        "Solo puede crear su propio usuario", "AUTH004");
                }
                user.setUserType(userType);
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.post()
                    .uri("/api/users/create")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(user),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al crear usuario: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error interno del servidor", "SRV001");
        }
    }

    @PostMapping("/user/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody User user) {
        log.info("Intento de login para usuario: {}", user.getUsername());
        
        try {
            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.post()
                    .uri("/api/users/login")
                    .bodyValue(user),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error en login: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error en el servicio de autenticación", "AUTH003");
        }
    }

    @GetMapping("/user/all")
    public ResponseEntity<Map<String, Object>> getAllUsers(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando todos los usuarios");
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para listar usuarios");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Invalido", "AUTH001");
            }
            
            // Solo admin puede ver todos los usuarios
            if (!auth.getUserType(token).equals("admin")) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, "Acceso denegado", "AUTH002");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.get()
                    .uri("/api/users/")
                    .header(HttpHeaders.AUTHORIZATION, token),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al obtener usuarios: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al recuperar usuarios", "SRV002");
        }
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable String id,
                                           @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Solicitando usuario ID: {}", id);
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para consultar usuario");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Invalido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            String requestingUserId = auth.getUserId(token);
            
            // Clients can only view their own information
            if (userType.equals("client") && !id.equals(requestingUserId)) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo puede ver su propia información", "AUTH005");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.get()
                    .uri("/api/users/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al obtener usuario: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al recuperar usuario", "SRV003");
        }
    }

    @PatchMapping("/user/update/{id}")
    public ResponseEntity<Map<String, Object>> updateUser(@PathVariable String id, 
                                           @RequestBody User user,
                                           @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Actualizando usuario ID: {}", id);
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para actualización");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Invalido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            String requestingUserId = auth.getUserId(token);
            
            // Clients can only update their own information
            if (userType.equals("client") && !id.equals(requestingUserId)) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo puede actualizar su propia información", "AUTH006");
            }
            
            // Providers can only update their own information
            if (userType.equals("provider") && !id.equals(requestingUserId)) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo puede actualizar su propia información", "AUTH006");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.patch()
                    .uri("/api/users/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(user),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al actualizar usuario: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al actualizar usuario", "SRV004");
        }
    }

    @DeleteMapping("/user/delete/{id}")
    public ResponseEntity<Map<String, Object>> deactivateUser(@PathVariable String id,
                                               @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Eliminando usuario ID: {}", id);
        
        try {
            if (!auth.validateToken(token)) {
                log.warn("Token inválido para eliminación");
                return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Token Inválido", "AUTH001");
            }
            
            String userType = auth.getUserType(token);
            String requestingUserId = auth.getUserId(token);
            
            // Clients can only deactivate themselves
            if (userType.equals("client") && !id.equals(requestingUserId)) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo puede desactivar su propia cuenta", "AUTH007");
            }
            
            // Providers can only deactivate themselves
            if (userType.equals("provider") && !id.equals(requestingUserId)) {
                return buildErrorResponse(HttpStatus.FORBIDDEN, 
                    "Solo puede desactivar su propia cuenta", "AUTH007");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.delete()
                    .uri("/api/users/delete/{id}", id)
                    .header(HttpHeaders.AUTHORIZATION, token),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error al eliminar usuario: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error al eliminar usuario", "SRV005");
        }
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
                        .body("{\"error\": \"Error durante el reintento\", \"code\": \"SRV006\"}");
                }
            } catch (Exception e) {
                log.error("Error inesperado", e);
                return ResponseEntity.internalServerError()
                    .body("{\"error\": \"Error interno del servidor\", \"code\": \"SRV000\"}");
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
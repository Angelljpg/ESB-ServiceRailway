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
import java.util.HashMap;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/esb/auth")
public class ESBAuthController {

    private final WebClient webClient;
    private final Auth auth;
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public ESBAuthController() {
        this.webClient = WebClient.builder()
            .baseUrl("https://usersrailway-production.up.railway.app")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.auth = new Auth();
    }

    @PostMapping("/password-token")
    public ResponseEntity<Map<String, Object>> generatePasswordToken(
            @RequestBody Map<String, String> request,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        log.info("Generating password reset token");
        
        try {
            String username = request.get("username");
            if (username == null || username.isEmpty()) {
                return buildErrorResponse(HttpStatus.BAD_REQUEST, 
                    "Username is required", "AUTH006");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.post()
                    .uri("/api/users/pass")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .bodyValue(request),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error generating password token: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error generating password token", "SRV006");
        }
    }

    @PostMapping("/reset-password/{token}")
    public ResponseEntity<Map<String, Object>> resetPassword(
            @PathVariable String token,
            @RequestBody Map<String, String> request) {
        log.info("Resetting password with token");
        
        try {
            String password = request.get("password");
            String repeatPassword = request.get("repeatPassword");
            
            if (password == null || repeatPassword == null) {
                return buildErrorResponse(HttpStatus.BAD_REQUEST, 
                    "Password and repeatPassword are required", "AUTH007");
            }
            
            if (!password.equals(repeatPassword)) {
                return buildErrorResponse(HttpStatus.BAD_REQUEST, 
                    "Passwords do not match", "AUTH008");
            }

            ResponseEntity<String> response = executeWithRetry(
                () -> webClient.post()
                    .uri("api/users/newpass/{token}", token)
                    .bodyValue(request),
                MAX_RETRIES
            );

            return ResponseEntity.status(response.getStatusCode())
                .body(buildSuccessResponse(response.getBody()));

        } catch (Exception e) {
            log.error("Error resetting password: {}", e.getMessage());
            return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Error resetting password", "SRV007");
        }
    }

    // Helper methods (same as in your other controllers)
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
                            log.warn("Attempt {} - Error {}, retrying...", 
                                    attemptCount[0], clientResponse.statusCode());
                            return Mono.empty();
                        }
                        return clientResponse.bodyToMono(String.class)
                            .flatMap(errorBody -> Mono.error(new WebClientResponseException(
                                clientResponse.statusCode().value(),
                                "Service error",
                                clientResponse.headers().asHttpHeaders(),
                                errorBody.getBytes(),
                                null)));
                    })
                    .bodyToMono(String.class)
                    .block();

                log.info("Request succeeded after {} attempts", attemptCount[0]);
                return ResponseEntity.ok(response);

            } catch (WebClientResponseException e) {
                log.error("Response error: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
                if (attemptCount[0] >= maxRetries || 
                    e.getStatusCode() != HttpStatus.BAD_GATEWAY) {
                    return ResponseEntity.status(e.getStatusCode())
                        .body(e.getResponseBodyAsString());
                }
                
                try {
                    long delay = RETRY_DELAY_MS * (long) Math.pow(2, attemptCount[0] - 1);
                    log.warn("Retrying in {} ms...", delay);
                    Thread.sleep(delay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error during retry");
                }
            } catch (Exception e) {
                log.error("Unexpected error", e);
                return ResponseEntity.internalServerError()
                    .body("Internal server error: " + e.getMessage());
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
            errorResponse.put("errorDetails", "Please contact the system administrator");
        }
        
        return ResponseEntity.status(status).body(errorResponse);
    }
}
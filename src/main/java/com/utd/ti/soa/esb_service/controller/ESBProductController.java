package com.utd.ti.soa.esb_service.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import com.utd.ti.soa.esb_service.model.Product;
import com.utd.ti.soa.esb_service.utils.Auth;

@RestController
@RequestMapping("/api/v1/esb")
public class ESBProductController {

    private final WebClient webClient = WebClient.create("https://productsrailway-production.up.railway.app/api/products");
    private final Auth auth = new Auth();

    // Obtener todos los productos
    @GetMapping("/products")
    public ResponseEntity<String> getAllProducts(@RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        if (!auth.validateToken(token)) {
            return ResponseEntity.status(401).body("Token Invalido");
        }

        String response = webClient.get()
            .uri("/")
            .retrieve()
            .bodyToMono(String.class)
            .block();
        return ResponseEntity.ok(response);
    }

    // Crear un nuevo producto
    @PostMapping("/products/create")
    public ResponseEntity<String> createProduct(@RequestBody Product product, @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        if (!auth.validateToken(token)) {
            return ResponseEntity.status(401).body("Token Invalido");
        }

        String response = webClient.post()
            .uri("/create")
            .bodyValue(product)
            .retrieve()
            .bodyToMono(String.class)
            .block();
        return ResponseEntity.status(201).body(response);
    }

    // Actualizar un producto
    @PatchMapping("/products/{id}")
    public ResponseEntity<String> updateProduct(@PathVariable String id, @RequestBody Product product, @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        if (!auth.validateToken(token)) {
            return ResponseEntity.status(401).body("Token Invalido");
        }

        String response = webClient.patch()
            .uri("/{id}", id)
            .bodyValue(product)
            .retrieve()
            .bodyToMono(String.class)
            .block();
        return ResponseEntity.ok(response);
    }

    // Dar de baja un producto
    @DeleteMapping("/products/{id}")
    public ResponseEntity<String> deleteProduct(@PathVariable String id, @RequestHeader(HttpHeaders.AUTHORIZATION) String token) {
        if (!auth.validateToken(token)) {
            return ResponseEntity.status(401).body("Token Invalido");
        }

        String response = webClient.delete()
            .uri("/{id}", id)
            .retrieve()
            .bodyToMono(String.class)
            .block();
        return ResponseEntity.ok(response);
    }
}

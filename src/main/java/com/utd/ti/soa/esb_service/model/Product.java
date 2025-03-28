package com.utd.ti.soa.esb_service.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Product {
    private String productName;
    private double unitPrice;
    private int stock;
    private int categoryId;
}

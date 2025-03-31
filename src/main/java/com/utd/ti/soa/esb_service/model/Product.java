package com.utd.ti.soa.esb_service.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Product {
    private String ProductName;
    private double UnitPrice;
    private int Stock;
    private int CategoryID;
}

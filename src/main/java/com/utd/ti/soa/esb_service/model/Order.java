package com.utd.ti.soa.esb_service.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Order {
    private int ClientID;
    private int ProductID;
    private int PurchasedQuantity;
    private String DeliveryAddress;
    private String ContactMethod;
    private String PaymentMethod; // Valores: "CASH", "DEBIT_CARD", "CREDIT_CARD"
}
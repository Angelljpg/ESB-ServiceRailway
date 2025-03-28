package com.utd.ti.soa.esb_service.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class User {
    private String username;
    private String phone;
    private String password;
    private String userType;
}

package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OrchestraDetails {
    private String details;

    public OrchestraDetails() {
    }

    public OrchestraDetails(String details) {
        this.details = details;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}

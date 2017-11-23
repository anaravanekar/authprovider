package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OrchestraResponseDetails {
    private List<OrchestraDetails> rows;

    public List<OrchestraDetails> getRows() {
        return rows;
    }

    public void setRows(List<OrchestraDetails> rows) {
        this.rows = rows;
    }
}

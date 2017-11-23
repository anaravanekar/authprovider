package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OrchestraObjectListResponse {
    private List<OrchestraObjectResponse> rows;
    private Map<String,Object> pagination;

    public List<OrchestraObjectResponse> getRows() {
        return rows;
    }

    public void setRows(List<OrchestraObjectResponse> rows) {
        this.rows = rows;
    }

    public Map<String, Object> getPagination() {
        return pagination;
    }

    public void setPagination(Map<String, Object> pagination) {
        this.pagination = pagination;
    }
}

package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OrchestraObjectResponse {
    private String label;
    private String details;
    private Map<String,OrchestraContent> content;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Map<String, OrchestraContent> getContent() {
        return content;
    }

    public void setContent(Map<String, OrchestraContent> content) {
        this.content = content;
    }
}

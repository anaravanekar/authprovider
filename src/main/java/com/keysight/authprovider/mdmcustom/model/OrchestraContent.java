package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OrchestraContent {
    private Object content;

    public OrchestraContent() {
    }

    public OrchestraContent(Object content) {
        this.content = content;
    }

    public Object getContent() {
        return content;
    }

    public void setContent(Object content) {
        this.content = content;
    }
}

package com.keysight.authprovider.mdmcustom.config.properties;

import com.keysight.authprovider.mdmcustom.config.properties.ws.Jitterbit;
import com.keysight.authprovider.mdmcustom.config.properties.ws.Orchestra;

public class RestProperties {
    private Orchestra orchestra;
    private Jitterbit jitterbit;

    public Orchestra getOrchestra() {
        return orchestra;
    }

    public void setOrchestra(Orchestra orchestra) {
        this.orchestra = orchestra;
    }

    public Jitterbit getJitterbit() {
        return jitterbit;
    }

    public void setJitterbit(Jitterbit jitterbit) {
        this.jitterbit = jitterbit;
    }
}

package com.keysight.authprovider.custom;

import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import com.orchestranetworks.service.UserReference;

/**
 * @author Derek Seabury
 * Allows the authentication of users based on HTTP request.
 * This allows for the CustomDirectoryInstance to access the extended functionality.
 */
public abstract class HttpAuthenticate  {
	public HttpAuthenticate(){
		// We need to be allocated dynamically so no parameters
		// Expect the updateSSOProperties() call before use.
	}
	public abstract UserReference GetUserFromHTTPRequest(final HttpServletRequest req );
	public abstract void updateSSOProperties(Properties props);
}

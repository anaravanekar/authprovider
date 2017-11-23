package com.keysight.authprovider.custom;

import com.orchestranetworks.service.UserReference;

import javax.servlet.http.HttpServletRequest;
import java.util.Properties;

/**
 * @author Derek Seabury
 * A custom external SSO instance must implement the methods in CheckSSO.
 * This allows for the CustomDirectoryInstance to access the extended functionality.
 */
public class SSOCheck extends HttpAuthenticate {
	public SSOCheck(){
		// We need to be allocated dynamically so no parameters
		// Expect the updateSSOProperties() call before use.
	}

	public UserReference GetUserFromHTTPRequest(final HttpServletRequest req ){
//		String uname = req.getParameter("user");
		String uname = req.getRemoteUser();
		//String uname = "administrator";
		if( uname!=null && !"".equals(uname) )
			return UserReference.forUser(uname);
		return null;
	}

	public void updateSSOProperties(Properties props){
		return;
	}
}

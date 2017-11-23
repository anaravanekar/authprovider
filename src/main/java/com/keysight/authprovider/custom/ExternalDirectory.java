package com.keysight.authprovider.custom;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import com.onwbp.adaptation.Adaptation;
import com.orchestranetworks.schema.Path;
import com.orchestranetworks.service.Session;
import com.orchestranetworks.service.UserReference;

/**
 * @author Derek Seabury
 * A custom external directory instance must implement the methods in ExternalDirectoryInstance.
 * This allows for the CustomDirectoryInstance to access the extended functionality.
 */
public interface ExternalDirectory  {
	
	public abstract HashMap <Path, String> updateUserProfile(
			final UserReference userReference, Adaptation user);
	public abstract boolean authenticateLogin(
			final String login, 
			final String password) throws Exception;
	public abstract Boolean isUserInRole(
			final UserReference user,
			final String roleId, final String roleLabel);
	public abstract void updateDirProperties(Properties props);
	public abstract String getUserAuthenticationURI(String fmt, Session sess);
		
	// Functions for testing
	public ArrayList<SimpleEntry<String, String>> getUserInfo(final String user);
	public void interact();
}

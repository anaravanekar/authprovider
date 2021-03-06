package com.keysight.authprovider.custom;

import com.onwbp.adaptation.Adaptation;
import com.onwbp.base.misc.StringUtils;
import com.orchestranetworks.ps.customDirectory.LogHelper;
import com.orchestranetworks.schema.Path;
import com.orchestranetworks.service.Session;
import com.orchestranetworks.service.UserReference;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import java.text.MessageFormat;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Properties;
import java.util.logging.Logger;

public class LdapActiveDirectory implements ExternalDirectory {

	private final static Logger logger = LoggerCustomDirectory.getLogger();

	private static final String PROPERTY_HEADER = "ebx.directory.ldap.";

	private static final String PATH = "path";

	private static final String BASE_DN = "baseDN";
	private static final String BIND_DN = "bindDN";
	private static final String USER_SEARCH = "search";
	private static final String REQ_TOLOGIN_MEMBERSHIP_BASE = "requiredToLogin.membershipBase";
	private static final String REQ_TOLOGIN_ROLE = "requiredToLogin.role";
	private static final String REQ_TOLOGIN_MEMBERSHIP_FILTER = "requiredToLogin.membershipFilter";
	
	private String ldapPath = null;
	private LdapName baseDN = null;
	private MessageFormat bindDN = null;
	private MessageFormat userSearch = null;

	private LdapName reqLogin_membershipBase = null;
	private MessageFormat reqLogin_membershipFilter = null;

	
	private Properties props = null;

	public HashMap<Path, String> updateUserProfile(UserReference userReference,
			Adaptation user) {
		return null;
	}

	public DirContext getDirContext(LdapName login, final String password){
		return connectToLDAP(login,password);
	}

	private DirContext connectToLDAP(LdapName login, final String password) {
		LogHelper.customDirectoryLog.debug("BEGIN connectToLDAP using LdapName="+login);
		Hashtable<String, String> env = new Hashtable<String, String>();

		env.put(Context.SECURITY_AUTHENTICATION, "none");
		if (login != null) {
			logger.info("Authenticating LDAP for login: "
					+ login + ".");
			// Bind as specified user
			env.put(Context.SECURITY_PRINCIPAL, login.toString());
			env.put(Context.SECURITY_CREDENTIALS, password);
			env.put(Context.SECURITY_AUTHENTICATION, "simple");
			
		} 
		env.put(Context.PROVIDER_URL, this.ldapPath);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.REFERRAL, "follow");

		try {
			DirContext ctx = new InitialDirContext(env);
//			logger.info("Returning dircontext " + ctx.getEnvironment());
			LogHelper.customDirectoryLog.debug("INITIALIZED DirContext ctx="+ctx);
			return ctx;
		} catch (Exception e) {
			if (login == null) {
				LogHelper.customDirectoryLog.error("Exception  connectToLDAP using LdapName="+login,e);
			}

			// User not found, or connection exception
			// In case there has been an update reload configuration
			updateDirProperties();
			return null;
		}
	}

	private LdapName getLoginForEbxUser(final String login, final String password) throws Exception {
		final DirContext ctx = connectToLDAP(login, password);
		if(ctx==null){
			return null;
		}
		LogHelper.customDirectoryLog.debug("BEGIN getLoginForEbxUser... getting LdapName using DirContext for login="+login);
		LdapName res = getLoginForEbxUser(login, ctx);
		try {
			LogHelper.customDirectoryLog.debug("END getLoginForEbxUser... received LdapName using DirContext for login="+login);
			LogHelper.customDirectoryLog.debug("CLOSING DirContext="+ctx);
			ctx.close();
		} catch (Exception e) {
			LogHelper.customDirectoryLog.error("ERROR CLOSING DirContext="+ctx,e);
			throw new Exception("LDAP authentication failed.. Error occurred while closing DirContext",e);
		}
		return res;
	}

	private DirContext connectToLDAP(String login, String password) {
		LogHelper.customDirectoryLog.debug("BEGIN connectToLDAP login="+login);
		Hashtable<String, String> env = new Hashtable<String, String>();
		MessageFormat bindDNFormat = ldapFormat(BIND_DN);
		String bindDN = bindDNFormat.format(new Object[] { login });

		LogHelper.customDirectoryLog.debug("Connecting to LDAP as bindDN." +  bindDN);

		env.put(Context.PROVIDER_URL, this.ldapPath);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.REFERRAL, "follow");
		env.put(Context.SECURITY_AUTHENTICATION, "none");
		env.put(Context.SECURITY_PRINCIPAL, bindDN);
		if (StringUtils.isNotEmpty(password)) {
			env.put(Context.SECURITY_CREDENTIALS, password);
			env.put(Context.SECURITY_AUTHENTICATION, "simple");
		}
		try {
			DirContext ctx = new InitialDirContext(env);
//			logger.info("LDAPContext " + ctx.getEnvironment());
			LogHelper.customDirectoryLog.debug("INITIALIZED DirContext ctx="+ctx);
			return ctx;
		} catch (Exception e) {
			LogHelper.customDirectoryLog.error("Exception connecting to LDAP ",e);
			// User not found, or connection exception
			// In case there has been an update reload configuration
			updateDirProperties();
			LogHelper.customDirectoryLog.debug("END connectToLDAP... Connection failed returning null");
			return null;
		}

	}

	private LdapName getLoginForEbxUser(final String login, final DirContext ctx) {
		if (this.userSearch == null)
			return null;
		//(&(objectClass=user)(samAccountName={0}))

		String filter = this.userSearch.format(new Object[] { login });
		//(&(objectClass=user)(samAccountName="user1"))

		String baseDNStr = ldapProp(BASE_DN);
		ArrayList<String> res = searchLdapForUser(ctx, baseDNStr, filter.replace("\"", ""));

		if (res == null || res.isEmpty()) {
			logger.info("User " + login + " not found.");
			return null;
		}
		if(null == this.baseDN){
			this.baseDN = ldapNameProp(BASE_DN);
		}
		logger.info("User " + login + " found.");

		LdapName user = null;
		try {
			if (this.baseDN != null && !res.get(0).toLowerCase().contains(this.baseDN.toString().toLowerCase())) {
				user = new LdapName(res.get(0) + "," + this.baseDN);
			} else {
				user = new LdapName(res.get(0));
			}
		} catch (Exception e) {
			LogHelper.customDirectoryLog.error("ERROR in getLoginForEbxUser",e);
		}
		logger.info("User " + user + " found.");

		return user;
	}
	private static String ldapFilterEscape(String input){
		String output = input.replaceAll("\\*", "\\\\2A");

		return output;
	}

	private ArrayList<String> searchLdapForUser(final DirContext extCtx,
			final String baseDN, String filter) {
		// Create the search controls         
		SearchControls searchCtls = new SearchControls();
		ArrayList<String> res = new ArrayList<String>();

		//Specify the attributes to return
		String returnedAtts[]={"sn","DistinguishedName", "samAccountName"};
		searchCtls.setReturningAttributes(returnedAtts);

		//Specify the search scope
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		try {
			// Search for objects using the filter
			NamingEnumeration<SearchResult> answer = extCtx.search(baseDN, filter, searchCtls);

			//Loop through the search results
			while (answer.hasMoreElements())
			{
				SearchResult sr = (SearchResult)answer.next();
				LogHelper.customDirectoryLog.debug(">>>" + sr.getName());
				Attributes attrs = sr.getAttributes();
				Attribute attr = attrs.get("DistinguishedName");
				res.add(attr.get().toString());
			}

			//extCtx.close();
		} catch (NamingException e) {
			LogHelper.customDirectoryLog.error("Error in searchLdapForUser",e);
		}
		return res;
	}

	public ArrayList<SimpleEntry<String, String>> searchUser(String user, String password) throws Exception {
		ArrayList<SimpleEntry<String, String>> userInfo = new ArrayList<SimpleEntry<String, String>>();


		DirContext ctx = connectToLDAP(user, password);
		if(ctx==null){
			throw new Exception("Error... could not connect to LDAP");
		}
		try {
			if (!isUserInRequiredForLoginRole(ctx, user)) {
				throw new Exception(String.format("Not authorized. user[%s] is not a member of required EBX group within Active Directory. ", user));
			}
			userInfo = getAttributes(new LdapName(ldapFormat(BIND_DN).format(new Object[] { user })), ctx);
		} finally {
			try {
				if (ctx != null){
					LogHelper.customDirectoryLog.debug("CLOSING DirContext="+ctx);
					ctx.close();
				}
			} catch (Exception e) {
				LogHelper.customDirectoryLog.error("ERROR CLOSING DirContext="+ctx,e);
				throw new Exception("LDAP authentication failed.. Error occurred while closing DirContext",e);
			}
		}
		return userInfo;
	}

	public boolean authenticateLogin(String user, String password) throws Exception {
		//Authenticating the user against the Active Directory
		LdapName login = getLoginForEbxUser(user, password);

		if(login == null){
			LogHelper.customDirectoryLog.debug("LdapName not found for login="+user+" ... returning false");
			return false;
		}

		DirContext ctx = connectToLDAP(login, password);
		try {
			if (!isUserInRequiredForLoginRole(ctx, user)) {
				throw new Exception(String.format("Not authorized. user[%s] is not a member of required EBX group within Active Directory. ", user));
			}
		} finally {
			try {
				if (ctx != null){
					LogHelper.customDirectoryLog.debug("CLOSING DirContext="+ctx);
					ctx.close();
				}
			} catch (Exception e) {
				LogHelper.customDirectoryLog.error("ERROR CLOSING DirContext="+ctx,e);
				throw new Exception("LDAP authentication failed.. Error occurred while closing DirContext",e);
			}
		}
		return true;
	}

	private String ldapProp(final String key) {
		String val = this.props.getProperty(PROPERTY_HEADER + key);
		if (null != val){
			final String value = val.replace("\"", "");
			return value;
		}
		return null;

	}

	public Boolean isUserInRequiredForLoginRole(DirContext ctx, final String login) {
		LogHelper.customDirectoryLog.debug("BEGIN isUserInRequiredForLoginRole using LDAP DirContext");
		if (this.reqLogin_membershipBase == null) {
			LogHelper.customDirectoryLog.info("No LDAP membership base defined. assuming it is disabled");
			return true;
		}

		final String filter;

		filter = this.reqLogin_membershipFilter.format(new Object[] { login });

		final ArrayList<String> fetchUserInRole = searchLdapForUser(ctx, this.reqLogin_membershipBase.toString(), filter);

		if (fetchUserInRole != null && !fetchUserInRole.isEmpty()) {
			LogHelper.customDirectoryLog.info("END isUserInRequiredForLoginRole using LDAP DirContext. Results found searching for " + login + " using "
					+ String.format("base[%s], filter[%s]", this.reqLogin_membershipBase, filter) + ".");
			return true;
		}

		LogHelper.customDirectoryLog.info(String.format("END isUserInRequiredForLoginRole using LDAP DirContext. No results found searching for %s using base[%s], filter[%s]",
				login, this.reqLogin_membershipBase, filter));
		return false;
	}

	public Boolean isUserInRole(UserReference user, String roleId,
			String roleLabel) {
		return null;
	}

	public void updateDirProperties(Properties p) {

		this.props = p;
		updateDirProperties();

	}

	public String getUserAuthenticationURI(String fmt, Session sess) {
		return null;
	}

	public ArrayList<SimpleEntry<String, String>> getUserInfo(String user) {
/*		InputStream input = null;
		try {
			input = new FileInputStream("E:\\tomcat1\\ebx.properties");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		// load a properties file
		Properties properties = new Properties();
		try {
			properties.load(input);
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.props=properties;
		this.ldapPath = "ldap://10.10.10.86:389";
		this.userSearch = ldapFormat("search");*/
//TODO remove

		ArrayList<SimpleEntry<String, String>> res = new ArrayList<SimpleEntry<String, String>>();
		try {
			DirContext ctx = connectToLDAP(user.split("\\|")[0],user.split("\\|")[1]);
			LdapName userName = getLoginForEbxUser(user.split("\\|")[0], ctx);
			ctx = connectToLDAP(user.split("\\|")[0],user.split("\\|")[1]);
			res = getAttributes(userName, ctx);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return res;
	}

	public void interact() {

	}
	private LdapName ldapNameProp(final String key) {
		String val = this.props.getProperty(PROPERTY_HEADER + key);
		if(null != val){
			final String value = val.replace("\"", "");

			LdapName name = null;
			try {
				name = new LdapName(value);

				return name;
			} catch (Exception e) {
				logger.severe("Invalid name for LDAP name  " + key
						+ ".  Be sure to double any \\ characters.");
			}

		}
		return null;		
	}
	private MessageFormat ldapFormat(final String key) {
		String val = this.props.getProperty(PROPERTY_HEADER + key);
		if(null != val){
			final String value = val.replace("\"", "");
			return new MessageFormat(value);
		}
		return null;

	}

	public void updateDirProperties() {
		logger.info("Reloading directory properties.");
		ldapPath = ldapProp(PATH);
		baseDN = ldapNameProp(BASE_DN);
		bindDN = ldapFormat(BIND_DN);
		
		reqLogin_membershipBase = ldapNameProp(REQ_TOLOGIN_MEMBERSHIP_BASE);
		reqLogin_membershipFilter = ldapFormat(REQ_TOLOGIN_MEMBERSHIP_FILTER);

		userSearch = ldapFormat(USER_SEARCH);
	}

	protected ArrayList<SimpleEntry<String, String>> getAttributes(
			final LdapName name, final DirContext extCtx) {
		ArrayList<SimpleEntry<String, String>> info = new ArrayList<SimpleEntry<String, String>>();
		try {
			DirContext ctx = extCtx;
			if (ctx == null)
				return info;//ctx = connectToLDAP();

			Attributes atts = ctx.getAttributes(name);
			for (NamingEnumeration<? extends Attribute> ae = atts.getAll(); ae
					.hasMore();) {
				Attribute attr = (Attribute) ae.next();
				String key = attr.getID();
				for (NamingEnumeration<?> values = attr.getAll(); values
						.hasMore();) {
					String value = (String) values.next().toString();
					info.add(new SimpleEntry<String, String>(key, value));
				}
			}
		} catch (Exception e) {
			LogHelper.customDirectoryLog.error("Error in getAttributes",e);
			return null;
		}
		return info;
	}
}

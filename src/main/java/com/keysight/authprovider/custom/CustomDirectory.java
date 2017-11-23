package com.keysight.authprovider.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keysight.authprovider.mdmcustom.config.properties.RestProperties;
import com.keysight.authprovider.mdmcustom.config.properties.ws.Orchestra;
import com.keysight.authprovider.mdmcustom.model.*;
import com.keysight.authprovider.mdmcustom.rest.client.OrchestraRestClient;
import com.onwbp.adaptation.*;
import com.onwbp.base.text.bean.LabelDescription;
import com.orchestranetworks.instance.Repository;
import com.orchestranetworks.schema.Path;
import com.orchestranetworks.service.*;
import com.orchestranetworks.service.directory.*;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.logging.Logger;

/**
 * @author Derek Seabury
 * @author Mickael GERMEMONT
 *
 * A DirectoryInstance supporting SSO and internal and external directories
 *
 */
public class CustomDirectory extends DirectoryDefault {

	private final static Logger logger = LoggerCustomDirectory.getLogger();

	protected Properties props;
	private ExternalDirectory extDir = null;
	private AdaptationHome aHome = null;
	private AdaptationTable dirTable = null;

	// Property strings
	protected static final String _ADMIN_USERID = "userCreationAcct";
	protected static final String _ENABLE_UPDATE = "enableProfileUpdate";
	protected static final String _ENABLE_LOGIN = "enableLogin";
	protected static final String _ENABLE_SSO = "enableSSO";
	protected static final String _ENABLE_BECOME = "enableBecome";
	protected static final String _ENABLE_CREATION = "enableUserCreation";
	protected static final String _LOGIN_URI = "loginURI";
	protected static final String _MEMBER_CACHE = "membershipCacheMs";

	// Property variables
	// Note that the default properties are defined in the updateDirProperties() function
	// and not by these initial values
	private UserReference adminUser = null;
	private boolean enableUpdate = false;
	private boolean enableLogin = true;
	private boolean enableBecome = true;
	private boolean enableUserCreation = false;
	private String loginURI = null;
	private long membershipCacheMs = 0;

	// Membership cache
	private HashMap<UserReference, UserMembershipCache> membershipCache;
	private class UserMembershipCache {
		private HashMap<Role, RoleMembership> cachedMembership;
	}
	private class RoleMembership {
		public boolean isMember = false;
		public long expiration = 0;
	}

	public CustomDirectory(AdaptationHome aHome){
		super(aHome);

		this.aHome = aHome;
		try{
			this.dirTable = aHome.findAdaptationOrNull(AdaptationName.forName("ebx-directory")).getTable(Path.parse("/directory/users"));
		} catch (Exception e){
			this.dirTable = null;
		}
		setExternalDirectory(new LdapActiveDirectory());

		updateDirProperties();
	}

	public void updateDirProperties(){
		Properties newProps = new Properties();
		try {
			String propPath = System.getProperty("ebx.properties", "ebx.properties");
			newProps.load(new FileInputStream(propPath));

			this.props = newProps;
			this.adminUser = UserReference.forUser(dirProp(_ADMIN_USERID,"admin"));
			this.enableUpdate= isTrueDirProp(_ENABLE_UPDATE, false);
			this.enableLogin = isTrueDirProp(_ENABLE_LOGIN, true);
			this.enableBecome = isTrueDirProp(_ENABLE_BECOME, true);
			this.enableUserCreation = isTrueDirProp(_ENABLE_CREATION, false);
			this.loginURI= dirProp(_LOGIN_URI, null);

			// Setup membership cache 
			try {
				this.membershipCacheMs = Integer.parseInt(dirProp(_MEMBER_CACHE, "0"));
			} catch (NumberFormatException e) {
				logger.warning("Could not parse ebx.properties "+ _MEMBER_CACHE + "value " + dirProp(_MEMBER_CACHE, "0"));
				this.membershipCacheMs = 0;
			}
			if( membershipCacheMs < 0 )
				membershipCache = null;
			else if( membershipCache==null )
				membershipCache = new HashMap<UserReference, UserMembershipCache>(20);

			if( extDir!=null )
				extDir.updateDirProperties(props);

		} catch (final Exception ex) {
			logger.severe("Exception updating directory properties:" + ex.getMessage());
		}
	}

	protected void setExternalDirectory( ExternalDirectory ext){
		this.extDir = ext;
		updateDirProperties();
	}

	protected Properties getProps(){
		return props;
	}

	private String dirProp(final String key, final String defaultValue){
		String val = props.getProperty("ebx.directory." + key);
		if( val==null || val.equals("") )
			return defaultValue;
		return val;
	}

	private boolean isTrueDirProp(String key, boolean defaultValue){
		return "true".equalsIgnoreCase(dirProp(key, defaultValue ? "true" : "false"));
	}

	@Override
	public URI getUserAuthenticationURI(Session sess) {
		if( this.loginURI==null )
			return null;

		String uriString = null;
		if( extDir!=null )
			uriString = extDir.getUserAuthenticationURI(loginURI, sess);
		if( uriString==null )
			uriString = loginURI;
		try{
			return new URI(uriString);
		} catch (Exception e){
			logger.severe("Could not parse ebx.properties "+ _LOGIN_URI + "value.");
		}
		return null;
	}

	protected final String _INTERNAL_SESSION = "internalSession";
	@Override
	public UserReference authenticateUserFromLoginPassword(String login,
														   String password) {
		UserReference user = null;
		logger.info("authenticateUserFromLoginPassword  ");

		// Note this is not .equals but object identity.
		if( login==_INTERNAL_SESSION ) {
			// If internal session creation call
			logger.info("Internal session ");
			return this.adminUser;
		}
		try {
			if( extDir!=null && extDir.authenticateLogin(login, password) ){
				user = UserReference.forUser(login);
			}
		} catch (Exception e) {
			logger.severe("Exception while authenticating against external directory: "+ e.getMessage());
		}

		if( user==null && !this.enableLogin ){
			// Not found externally and internal directory is disabled
			logger.info("Denying user/password login for '"+login+"'.");

			updateDirProperties();
			throw new AuthenticationException("Please request access to this system.");
		}
		if( user==null ){
			logger.info("Authenticate by default directory"+login+"'.");
			user= super.authenticateUserFromLoginPassword(login, password);
		}

		if( user==null ){
			// Ensure we are up to date if we are rejecting logins
			updateDirProperties();
			return null;
		}
		UserEntity userEntity = null;
		if( !isUserDefined(user) ){
			if( this.enableUserCreation ){
				createUser(user);
			} else {
				// Ensure we are up to date if we are rejecting logins
				updateDirProperties();
				logger.info("User '" + login + "' not found.");
				throw new AuthenticationException("User '" + login + "' not found.\nPlease request access to this EBX system.");
			}
		}
		if( this.enableUpdate && extDir!=null && !"admin".equals(login)){
/*			userEntity = DirectoryDefaultHelper.findUser(user,this);
			List<Role> specificRoles = userEntity.getSpecificRoles();
			for(Role role: specificRoles){
				logger.info("name="+role.getRoleName());
				logger.info("lable="+role.getLabel());
			}*/
			//updateUser(user);
			updateRole(user,extDir.getUserInfo(login+"|"+password));
		}

		// Clear membership cache if any
		if( this.membershipCache!=null ){
			this.membershipCache.remove(user);
		}

		return user;
	}

	private void updateRole(UserReference user,List<AbstractMap.SimpleEntry<String, String>> userInfo){
		String userId = user.getUserId();
		String userFirstName = "";
		String userLastName = "";
		String userEmail = null;
		HashMap<String,String> ebxRoles = new HashMap<>();
 		OrchestraObjectList orchestraObjectList = new OrchestraObjectList();
		List<OrchestraObject> rows = new ArrayList<>();

		try {
			OrchestraRestClient orchestraRestClient = new OrchestraRestClient(getRestProperties());
			OrchestraObjectListResponse orchestraObjectListResponse = orchestraRestClient.get("Bebx-directory","ebx-directory","directory/roles",null);
			if(orchestraObjectListResponse!=null && orchestraObjectListResponse.getRows() != null && !orchestraObjectListResponse.getRows().isEmpty()) {
				List<OrchestraObjectResponse> resultRows = orchestraObjectListResponse.getRows();
				for(OrchestraObjectResponse response:resultRows){
					String roleName = response.getContent().get("name").getContent().toString();
					//ebxRoles.put("CN="+roleName+",CN=Users,DC=KEYSIGHT,DC=COM",roleName);
					ebxRoles.put("CN="+roleName+",CN=Users,DC=AD,DC=KEYSIGHT,DC=COM",roleName);
				}
			}
			for(AbstractMap.SimpleEntry entry:userInfo){
				if("memberOf".equals(entry.getKey())){
					if(ebxRoles.get(entry.getValue())!=null) {
						OrchestraObject orchestraObject = new OrchestraObject();
						Map<String,OrchestraContent> content = new HashMap<String, OrchestraContent>();
						content.put("user",new OrchestraContent(userId));
						content.put("role",new OrchestraContent(ebxRoles.get(entry.getValue())));
						orchestraObject.setContent(content);
						rows.add(orchestraObject);
					}
				}else if("displayName".equals(entry.getKey()) && entry.getValue()!=null){
					String displayname = entry.getValue().toString();
					if(displayname.contains(" ")){
						displayname = displayname.split("\\s")[0];
					}
					if(displayname.contains(",")){
						userFirstName=displayname.split(",")[1];
						userLastName=displayname.split(",")[0];
					}else{
						userLastName=displayname;
					}
				}else if("mail".equals(entry.getKey()) && entry.getValue()!=null){
					userEmail=entry.getValue().toString();
				}
			}
			orchestraObjectList.setRows(rows);
			Map<String, String> parameters = new HashMap<String, String>();
			parameters.put("updateOrInsert", "true");
			ObjectMapper mapper = new ObjectMapper();
			Response response = orchestraRestClient.insert("Bebx-directory","ebx-directory","directory/usersRoles",orchestraObjectList,parameters);

			OrchestraObjectList userObjectList = new OrchestraObjectList();
			List<OrchestraObject> userRows = new ArrayList<>();
			OrchestraObject userObject = new OrchestraObject();
			Map<String,OrchestraContent> userFields = new HashMap<String, OrchestraContent>();
			userFields.put("login",new OrchestraContent(userId));
			userFields.put("firstName",new OrchestraContent(userFirstName));
			userFields.put("lastName",new OrchestraContent(userLastName));
			userFields.put("email",new OrchestraContent(userEmail));
			userObject.setContent(userFields);
			userRows.add(userObject);
			userObjectList.setRows(userRows);
			response = orchestraRestClient.insert("Bebx-directory","ebx-directory","directory/users",userObjectList,parameters);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void updateUser(UserReference user){
		if( this.dirTable==null ){
			this.dirTable = aHome.findAdaptationOrNull(AdaptationName.forName("ebx-directory")).getTable(Path.parse("/directory/users"));
		}

		// Update EBX user record
		try {
			ProgrammaticService svc = ProgrammaticService.createForSession(
					aHome.getRepository().createSessionFromLoginPassword(this._INTERNAL_SESSION, ""), aHome);
			final Adaptation userRecord =
					dirTable.lookupAdaptationByPrimaryKey(PrimaryKey.parseString(user.getUserId()));
			HashMap <Path, String> params = extDir.updateUserProfile(user, userRecord);
			if( params.size() == 0 )
				return;

			@SuppressWarnings("unchecked")
			final HashMap <Path, String> updates = (HashMap<Path, String>)params.clone();
			Procedure proc = new Procedure()
			{
				public void execute(ProcedureContext pContext) throws Exception
				{
					ValueContextForUpdate vc = pContext.getContext(userRecord.getAdaptationName());
					pContext.setAllPrivileges(true);
					for(Path param : updates.keySet())
						vc.setValue(updates.get(param), param);
					pContext.doModifyContent(userRecord, vc);
					pContext.setAllPrivileges(false);
				}
			};
			ProcedureResult res = svc.execute(proc);
			res.hasFailed();
		} catch (Exception e) {
			String msg = "Error updading user profile: "+e.getMessage();
			logger.warning(msg);
			e.printStackTrace();
		}
	}

	@Override
	public UserReference authenticateUserFromHttpRequest(
			HttpServletRequest req) throws AuthenticationException {
		String uname = null;
		UserReference user = null;
		String password = null;

		// If in a SOAP request use secondary authentication
		if( req.getHeader("SOAPAction")!=null )
			return null;

		DirectoryDefault dir = null;
		try{
			dir = DirectoryDefault.getInstance(Repository.getDefault());
		} catch ( Exception e ){
			throw new AuthenticationException("Could not find directory instance.");
		}


		if( user==null && this.enableLogin ){
			user = super.authenticateUserFromHttpRequest(req);
		}

		if( user==null && this.enableLogin ){
			// Try with URL parameters
			uname = req.getParameter("login");
			password = req.getParameter("password");
			if( uname!=null && password!=null )
				user = authenticateUserFromLoginPassword(uname, password);
		}

		if( user==null ) {
			// Ensure we are up to date if we are rejecting logins
			updateDirProperties();
			return null;
		}

		// User is defined and authenticated
		String become = req.getParameter("become");
		if( become!=null && this.enableBecome && isUserInRole(user, UserReference.ADMINISTRATOR) ){
			UserReference beUser = null;
			if(become != null )
				beUser = UserReference.forUser(become);
			if(beUser != null && dir.isUserDefined(beUser) ){
				logger.info("Allowing user '" + uname + "' to become user '" + become +"'");
				user = beUser;
			}
		}

		// Update from external directory
		// By updating the 'become' user we create a mechanism to mass update users 
		if( user!=null && extDir!=null && this.enableUpdate){
			updateUser(user);
		}

		// Clear membership cache if any
		if( this.membershipCache!=null ){
			this.membershipCache.remove(user);
		}

		return user;
	}

	@Override
	public boolean isUserInRole(final UserReference user, final Role role) {
		Boolean isMember = null;
		UserMembershipCache userMemberships = null;
		RoleMembership cachedMembership = null;
		// Check cache
		if( membershipCache!=null){
			userMemberships = membershipCache.get(user);
			if( userMemberships==null ){
				userMemberships = new UserMembershipCache();
				userMemberships.cachedMembership = new HashMap<Role, RoleMembership>(5);
				membershipCache.put(user, userMemberships);
			} else {
				cachedMembership = userMemberships.cachedMembership.get(role);
				if( cachedMembership!=null && (cachedMembership.expiration==0 || cachedMembership.expiration > System.currentTimeMillis()) )
					// Use cache value
					return cachedMembership.isMember;
			}
		}

		if( extDir!=null )
			// Check external directory
			isMember = extDir.isUserInRole(user, role.getRoleName(), role.getLabel());

		if( isMember==null || isMember==false)
			// Not cached, not an external group, check EBX membership 
			isMember = super.isUserInRole(user, role);

		// Update cache
		if( membershipCache!=null ){
			cachedMembership = new RoleMembership();
			cachedMembership.isMember = isMember;
			if( this.membershipCacheMs==0 )
				cachedMembership.expiration = 0;
			else
				cachedMembership.expiration = this.membershipCacheMs + System.currentTimeMillis();
			userMemberships.cachedMembership.put(role, cachedMembership);
		}
		return isMember;
	}

	private void createUser(final UserReference user){
		createUser(user, "nil");
	}

	private void createUser(final UserReference user, final String cred){
		final UserEntity userEntity = DirectoryDefaultHelper.newUser(user, this);
		userEntity.setBuiltInAdministrator(false);
		userEntity.setReadOnly(false);

		DirectoryDefaultHelper.saveUser(userEntity, "", this);

//		if( this.dirTable==null ){
//			this.dirTable = aHome.findAdaptationOrNull(AdaptationName.forName("ebx-directory")).getTable(Path.parse("/directory/user"));
//		}

//		final Procedure addUserProc = new Procedure() {
//
//			final Path loginPath = Path.parse("./login");
//			final Path pwPath = Path.parse("./password");
////			final Path pwChangePath = Path.parse("./passwordMustChange");
//			final Path adminPath = Path.parse("./builtInRoles/readOnly");
//			final Path readOnlyPath = Path.parse("./builtInRoles/readOnly");
//
//			@Override
//			public void execute(final ProcedureContext pContext) throws Exception {
//				final BuiltInRoles builtInRole = new BuiltInRoles();
//
//				builtInRole.setAdministrator(false);
//				builtInRole.setReadOnly(false);
//				pContext.setAllPrivileges(true);
//				final ValueContextForUpdate vc = pContext.getContextForNewOccurrence(dirTable);
////				vc.setValue(user.getUserId(), loginPath);
////				vc.setValueFromXsString("", pwPath);
////				vc.setValueFromXsString("false", adminPath);
////				vc.setValueFromXsString("false", readOnlyPath);
//				pContext.doCreateOverwriting(vc, dirTable);
//				pContext.setAllPrivileges(false);
//			}
//		};
//
//		final ProgrammaticService svc = ProgrammaticService.createForSession(
//				aHome.getRepository().createSessionFromLoginPassword(this._INTERNAL_SESSION, ""), aHome);
//		svc.execute(addUserProc);
	}

	/* Capability extension to support need to access role descriptions.  
	 * This should be added to base Role API and then this can be deprecated. */
	public String getRoleDescription(Role role, Locale locale){
		if( role.isBuiltIn() )
			return "EBX Built-in Role " + role.getLabel();
		try{
			AdaptationTable roleTable = this.dirTable.getContainerAdaptation().getTable(Path.parse("/directory/roles"));
			Adaptation aRole = roleTable.lookupAdaptationByPrimaryKey(PrimaryKey.parseString(role.getRoleName()));
			LabelDescription doc= (LabelDescription) aRole.get(Path.parse("./documentation"));
			if( doc.getLocalizedDocumentation(locale)==null )
				return "";
			final String desc = doc.getLocalizedDocumentation(locale).getDescription();
			if( desc==null )
				return "";
			return desc;
		} catch (Exception e){
			return "";
		}
	}

	/* Default factory for custom directory 
	 * @see com.orchestranetworks.service.directory.DirectoryDefaultFactory#createDirectory(com.onwbp.adaptation.AdaptationHome)
	 */
	public static class Factory extends DirectoryDefaultFactory {
		/* Create a custom directory without an external directory. 
		 * A simple extension of the DirectoryDefaultFactory.
		 * 
		 * @see com.orchestranetworks.service.directory.DirectoryDefaultFactory#createDirectory(com.onwbp.adaptation.AdaptationHome)
		 */
		@Override
		public Directory createDirectory(AdaptationHome aHome) throws Exception {
			// Returns a base directory with no external secondary
			Directory dir = new CustomDirectory(aHome);
			return dir;
		}
	}

	private RestProperties getRestProperties(){
		RestProperties restProperties = new RestProperties();
		Orchestra orchestra = new Orchestra();
		orchestra.setHost("localhost");
		orchestra.setSsl("false");
		orchestra.setUsername("admin");
		orchestra.setPassword("Serene*123");
		orchestra.setPort("9999");
		orchestra.setBaseURI("/ebx-dataservices/rest/data/");
		orchestra.setVersion("v1");
		orchestra.setConnectTimeout(5000);
		orchestra.setReadTimeout(70000);
		restProperties.setOrchestra(orchestra);
		return restProperties;
	}
}

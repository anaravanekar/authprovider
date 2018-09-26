package com.orchestranetworks.ps.customDirectory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keysight.authprovider.custom.ExternalDirectory;
import com.keysight.authprovider.custom.LdapActiveDirectory;
import com.keysight.authprovider.custom.LoggerCustomDirectory;
import com.keysight.authprovider.mdmcustom.config.properties.RestProperties;
import com.keysight.authprovider.mdmcustom.config.properties.ws.Orchestra;
import com.keysight.authprovider.mdmcustom.model.*;
import com.keysight.authprovider.mdmcustom.rest.client.OrchestraRestClient;
import com.onwbp.adaptation.*;
import com.onwbp.core.ui.UIBuilder;
import com.orchestranetworks.instance.HomeKey;
import com.orchestranetworks.instance.Repository;
import com.orchestranetworks.schema.Path;
import com.orchestranetworks.service.Profile;
import com.orchestranetworks.service.Role;
import com.orchestranetworks.service.UserReference;
import com.orchestranetworks.service.directory.AuthenticationException;
import com.orchestranetworks.service.directory.Directory;
import com.orchestranetworks.service.directory.DirectoryDefault;
import com.orchestranetworks.service.directory.ProfileListContext;
import com.orchestranetworks.ui.UICSSCatalog;
import com.orchestranetworks.ui.UIHttpManagerComponent;
import com.orchestranetworks.ui.UIHttpManagerComponent.Scope;
import com.orchestranetworks.ui.UIHttpManagerComponentBridge;
import org.jasypt.util.text.BasicTextEncryptor;
import org.yaml.snakeyaml.Yaml;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * @author Mickael GERMEMONT
 *
 */
public class HistoryCustomDirectory extends Directory {

	private final static Logger LOGGER = LoggerCustomDirectory.getLogger();

	private final CustomDirectory customDirectory;

	private ExternalDirectory extDir = null;

	private final Repository repo;

	protected Properties props;
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

	private Map<String,Object> propertiesCache;

	protected HistoryCustomDirectory(final AdaptationHome arg0) {
		super();
		this.customDirectory = null; // NOT using EBX out of the box directory
		// this.customDirectory = new CustomDirectory(arg0); // using EBX out of the box directory
		this.repo = arg0.getRepository();
		this.extDir = new LdapActiveDirectory();
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

			if( extDir!=null )
				extDir.updateDirProperties(props);

		} catch (final Exception ex) {
			LOGGER.severe("Exception updating directory properties:" + ex.getMessage());
		}
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


	private final static class AdaptationGetValueWrapper<E> {

		private final Adaptation record;

		public AdaptationGetValueWrapper(final Adaptation record) {
			this.record = record;
		}

		public Adaptation getRecord() {
			return record;
		}

		public E get(final Path field) {
			if (record == null) {
				return null;
			}

			final Object value = record.get(field);
			if (value == null) {
				return null;
			}

			return (E) value;
		}
	}

	public final static class HistoryDao {
		static final String historyDataspaceId = "UserDirectory";
		static final String historyDatasetId = "UserDirectory";
		static final Path toUserTable = Path.parse("/root/Users");
		static final Path _user_email = Path.parse("./email");
		static final Path _user_password = Path.parse("./password");
		static final Path _user_isEbxAdmin = Path.parse("./isEbxAdmin");

		static final Path _user_firstName = Path.parse("./firstName");
		static final Path _user_lastName = Path.parse("./lastName");

		static final Path toRoleTable = Path.parse("/root/Roles");
		static final Path toUserRoleTable = Path.parse("/root/UserRole");
		static final Path _userRole_role = Path.parse("./roleId");
		static final Path _userRole_user = Path.parse("./userId");

		private final AdaptationTable roleTable;
		private final AdaptationTable userTable;
		private final AdaptationTable userRoleTable;

		public HistoryDao(final Repository repository) {
			final AdaptationHome historyDirectory = repository.lookupHome(HomeKey.forBranchName(historyDataspaceId));
			if (historyDirectory == null) {
				this.roleTable = this.userTable = this.userRoleTable = null;
				return;
			}

			final Adaptation historyDataset = historyDirectory.findAdaptationOrNull(AdaptationName.forName(historyDatasetId));
			if (historyDataset == null) {
				this.roleTable = this.userTable = this.userRoleTable = null;
				return;
			}

			this.roleTable = historyDataset.getTable(toRoleTable);
			this.userTable = historyDataset.getTable(toUserTable);
			this.userRoleTable = historyDataset.getTable(toUserRoleTable);
		}

		public boolean existHelper(final AdaptationTable aTable, final String aId) {
			if (aTable == null) {
				return false;
			}

			final Adaptation record = aTable.lookupAdaptationByPrimaryKey(PrimaryKey.parseString(aId));
			return record != null;
		}

		public boolean existUser(final String userId) {
			return existHelper(this.userTable, userId);
		}

		public Adaptation lookupHelper(final AdaptationTable aTable, final String aId) {
			if (aTable == null) {
				return null;
			}

			final Adaptation record = aTable.lookupAdaptationByPrimaryKey(PrimaryKey.parseString(aId));
			return record;
		}

		public Adaptation lookupUser(final String userId) {
			return lookupHelper(this.userTable, userId);
		}

		public String displayUser(final String userId) {
			final AdaptationGetValueWrapper<String> user = new AdaptationGetValueWrapper<String>(lookupUser(userId));
			final String firstname = user.get(_user_firstName);
			final String lastname = user.get(_user_lastName);

			return firstname + " " + lastname;
		}

		public String lookupUserEmail(final String userId) {
			return new AdaptationGetValueWrapper<String>(lookupUser(userId)).get(_user_email);
		}

		public String lookupUserPassword(final String userId) {
			return new AdaptationGetValueWrapper<String>(lookupUser(userId)).get(_user_password);
		}

		public AdaptationTable getRoleTable() {
			return roleTable;
		}

		public boolean existRole(final String roleId) {
			return existHelper(this.roleTable, roleId);
		}

		public Adaptation lookupRole(final String roleId) {
			return lookupHelper(this.roleTable, roleId);
		}

		public AdaptationTable getUserRoleTable() {
			return userRoleTable;
		}

		public AdaptationTable getUserTable() {
			return userTable;
		}
	}

	@Override
	public UserReference authenticateUserFromHttpRequest(HttpServletRequest req) throws AuthenticationException {
		LOGGER.fine(String.format("historydir.authenticateUserFromHttpRequest[req]..."));
		final UserReference user = sso(req);

		if (user == null) {
			LOGGER.fine("sso didnt work. unknown login request");
			return null;
		}

		if (isUserDefined(user) == false) {
			LOGGER.fine("sso worked but unknown login in the directories");
			return null;
		}

		LOGGER.fine(String.format("historydir.urlparameter.become=%s", req.getParameter("become")));

		if (customDirectory != null) {
			final UserReference became = customDirectory.become(this, user, req.getParameter("become"));
			if (became != null) {
				LOGGER.fine("became!");
				return became;
			} else {
				LOGGER.fine("not became");
			}
		}

		return user;
	}

	UserReference sso(final HttpServletRequest req) {

		final UserReference user;

		if (req.getRemoteUser() != null) {
			// SSO feature
			LOGGER.fine(String.format("authenticateUserFromHttpRequest: AUTH-SSO"));

			String uname = req.getRemoteUser();
			if ((uname != null) && (!"".equals(uname))) {
				if (uname.contains("\\")) {
					uname = uname.split("\\\\")[1];
				}

				return UserReference.forUser(uname.toUpperCase());
			}

			return null;

		} else if (customDirectory != null) {
			LOGGER.fine(String.format("authenticateUserFromHttpRequest: AUTH-DEFAULT"));
			user = customDirectory.authenticateUserFromHttpRequest(req);
		} else {
			return null;
		}

		return user;
	}

	@Override
	public UserReference authenticateUserFromLoginPassword(final String aLogin, final String aPassword) {
		LOGGER.fine(String.format("authenticateUserFromLoginPassword[%s][pwd]...", aLogin));
		if (customDirectory != null) {
			final UserReference defaultResult = customDirectory.authenticateUserFromLoginPassword(aLogin, aPassword);
			if (defaultResult != null) {
				return defaultResult;
			}
		}

		final Adaptation userRecord = new HistoryDao(this.repo).lookupUser(aLogin.toLowerCase());
		/*if (userRecord == null) {
			return null;
		}*/

		final String realUserPassword = userRecord!=null?userRecord.getString(HistoryDao._user_password):null;
		final String inputUserPassword = DirectoryDefault.encryptString(aPassword);

		if (realUserPassword!=null && realUserPassword.equals(inputUserPassword)) {
			Runnable updateUserInfoInCustomDirectory = () -> {
				try {
					upsertUser(aLogin,extDir.searchUser(aLogin, aPassword));
				} catch (Exception e) {
					LOGGER.severe("Exception while updating user info in custom directory from LDAP : "+ e.getMessage());
				}
			};
			new Thread(updateUserInfoInCustomDirectory).start();
			return UserReference.forUser(aLogin.toLowerCase());
		} else if(extDir!=null){
			ArrayList<AbstractMap.SimpleEntry<String, String>> userInfo = null;
			try{
				userInfo = extDir.searchUser(aLogin, aPassword);
			}catch(Exception e){
				LOGGER.severe("Exception while authenticating against external directory: "+ e.getMessage());
			}
			if(userInfo!=null && !userInfo.isEmpty()){
				upsertUser(aLogin.toLowerCase(),userInfo);
				return UserReference.forUser(aLogin.toLowerCase());
			} else {
				// Ensure we are up to date if we are rejecting logins
				updateDirProperties();
				LOGGER.info("User '" + aLogin + "' not found.");
				throw new AuthenticationException("User '" + aLogin + "' not found.\nPlease request access to this EBX system.");
			}
		}
		return null;
	}

	private void upsertUser(String userId,List<AbstractMap.SimpleEntry<String, String>> userInfo){
		String userFirstName = "";
		String userLastName = "";
		String userEmail = null;
		HashMap<String,String> ebxRoles = new HashMap<>();
		OrchestraObjectList orchestraObjectList = new OrchestraObjectList();
		List<OrchestraObject> rows = new ArrayList<>();

		try {
			OrchestraRestClient orchestraRestClient = new OrchestraRestClient(getRestProperties());
			OrchestraObjectListResponse orchestraObjectListResponse = orchestraRestClient.get("BUserDirectory","UserDirectory","root/Roles",null);
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
						content.put("userId",new OrchestraContent(userId.toLowerCase()));
						content.put("roleId",new OrchestraContent(ebxRoles.get(entry.getValue())));
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
			Response response = orchestraRestClient.insert("BUserDirectory","UserDirectory","root/UserRole",orchestraObjectList,parameters);

			OrchestraObjectList userObjectList = new OrchestraObjectList();
			List<OrchestraObject> userRows = new ArrayList<>();
			OrchestraObject userObject = new OrchestraObject();
			Map<String,OrchestraContent> userFields = new HashMap<String, OrchestraContent>();
			userFields.put("userId",new OrchestraContent(userId.toLowerCase()));
			userFields.put("firstName",new OrchestraContent(userFirstName));
			userFields.put("lastName",new OrchestraContent(userLastName));
			userFields.put("email",new OrchestraContent(userEmail));
			userFields.put("isEbxAdmin",new OrchestraContent(false));
			userObject.setContent(userFields);
			userRows.add(userObject);
			userObjectList.setRows(userRows);
			response = orchestraRestClient.insert("BUserDirectory","UserDirectory","root/Users",userObjectList,parameters);
			userFields.remove("userId");
			userFields.remove("isEbxAdmin");
			userFields.put("login",new OrchestraContent(userId.toLowerCase()));
			userObject.setContent(userFields);
			userRows.add(userObject);
			userObjectList.setRows(userRows);
			response = orchestraRestClient.insert("BReference","ReferenceData","root/AssignTo",userObjectList,parameters);
		} catch (IOException e) {
			LOGGER.severe("Error upserting user in UserDirectory. "+e.getMessage());
		}
	}

	public List<Role> getAllSpecificRoles() {
		final Long start = System.nanoTime();

		final List<Role> results = new ArrayList<Role>();

		if (customDirectory != null) {
			results.addAll(customDirectory.getAllSpecificRoles());
		}

		final AdaptationTable roleTable = new HistoryDao(repo).getRoleTable();
		if (roleTable != null) {
			final List<Adaptation> records = roleTable.selectOccurrences(null);
			for (final Adaptation record : records) {
				results.add(Role.forSpecificRole(record.getOccurrencePrimaryKey().format()));
			}
		}

		LogHelper.customDirectoryPerformanceLog.debug("getAllSpecificRoles::" + (System.nanoTime() - start));

		return results;
	}

	public List<UserReference> getAllUserReferences() {
		final Long start = System.nanoTime();

		final List<UserReference> results = new ArrayList<UserReference>();

		if (customDirectory != null) {
			results.addAll(customDirectory.getAllUserReferences());
		}

		final AdaptationTable userTable = new HistoryDao(repo).getUserTable();
		if (userTable != null) {
			final List<Adaptation> records = userTable.selectOccurrences(null);
			for (final Adaptation record : records) {
				results.add(UserReference.forUser(record.getOccurrencePrimaryKey().format()));
			}
		}

		LogHelper.customDirectoryPerformanceLog.debug("getAllUserReferences::" + (System.nanoTime() - start));

		return results;
	}

	@Override
	public String displaySpecificRole(final Role arg0, final Locale arg1) {
		final Long start = System.nanoTime();
		final String result;

		if (customDirectory != null && (arg0.isBuiltIn() || arg0.isSpecificRole() == false)) {
			result = customDirectory.displaySpecificRole(arg0, arg1);
		} else {
			result = arg0.getRoleName();
		}

		LogHelper.customDirectoryPerformanceLog.debug("displaySpecificRole::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public String displayUser(final UserReference arg0, final Locale arg1) {
		final Long start = System.nanoTime();

		final String result;
		if (customDirectory != null && customDirectory.isUserDefined(arg0)) {
			result = customDirectory.displayUser(arg0, arg1);
		} else {
			result = new HistoryDao(Repository.getDefault()).displayUser(arg0.getUserId());
		}

		LogHelper.customDirectoryPerformanceLog.debug("displayUser::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public String displayUserWithSalutation(final UserReference arg0, final Locale arg1) {
		final Long start = System.nanoTime();

		final String result = displayUser(arg0, arg1);

		LogHelper.customDirectoryPerformanceLog.debug("displayUserWithSalutation::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public String getUserEmail(final UserReference arg0) {
		final Long start = System.nanoTime();

		final String result;

		if (customDirectory != null && customDirectory.isUserDefined(arg0)) {
			result = customDirectory.getUserEmail(arg0);
		} else {
			result = new HistoryDao(repo).lookupUserEmail(arg0.getUserId());
		}

		LogHelper.customDirectoryPerformanceLog.debug("getUserEmail::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public List<UserReference> getUsersInRole(final Role role) {
		final Long start = System.nanoTime();

		final List<UserReference> results = new ArrayList<UserReference>();

		if (customDirectory != null) {
			final List<UserReference> defaultUsersInRole = customDirectory.getUsersInRole(role);
			results.addAll(defaultUsersInRole);
		}

		if (role.isBuiltInAdministrator()) {
			final String predicateIsAdmin = String.format("%s = true", HistoryDao._user_isEbxAdmin.format());
			final List<Adaptation> records = new HistoryDao(repo).getUserTable().selectOccurrences(predicateIsAdmin);
			if (records != null) {
				for (final Adaptation userIsAdminRecord : records) {
					results.add(UserReference.forUser(userIsAdminRecord.getOccurrencePrimaryKey().format()));
				}
			}
		} else {
			final String predicate = String.format("%s = '%s'", HistoryDao._userRole_role.format(), role.getRoleName());

			final AdaptationTable userRoleTable = new HistoryDao(repo).getUserRoleTable();
			if (userRoleTable != null) {
				final List<Adaptation> records = userRoleTable.selectOccurrences(predicate);
				for (final Adaptation record : records) {
					results.add(UserReference.forUser(record.getString(HistoryDao._userRole_user)));
				}
			}
		}

		LogHelper.customDirectoryPerformanceLog.debug("getUsersInRole::" + (System.nanoTime() - start));

		return results;
	}

	public List<Role> getRolesForUser(final UserReference userReference) {
		final Long start = System.nanoTime();

		final List<Role> rolesForUser = new ArrayList<Role>();
		final List<Role> defaultRoles = getAllSpecificRoles();

		for (final Role role : defaultRoles) {
			if (isUserInRole(userReference, role)) {
				rolesForUser.add(role);
			}
		}

		LogHelper.customDirectoryPerformanceLog.debug("getRolesForUser::" + (System.nanoTime() - start));

		return rolesForUser;
	}

	@Override
	public boolean isRoleStrictlyIncluded(final Role arg0, final Role arg1) {
		final Long start = System.nanoTime();

		LogHelper.customDirectoryPerformanceLog.debug("isRoleStrictlyIncluded::" + (System.nanoTime() - start));

		return false;
	}

	@Override
	public boolean isSpecificRoleDefined(final Role arg0) {
		final Long start = System.nanoTime();

		final boolean result;

		if (customDirectory != null) {
			final boolean defaultResult = customDirectory.isSpecificRoleDefined(arg0);
			if (defaultResult) {
				return true;
			}
		}

		result = new HistoryDao(repo).existRole(arg0.getRoleName());

		LogHelper.customDirectoryPerformanceLog.debug("isSpecificRoleDefined::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public boolean isUserDefined(final UserReference arg0) {
		final Long start = System.nanoTime();

		if (customDirectory != null) {
			final boolean defaultResult = customDirectory.isUserDefined(arg0);

			if (defaultResult) {
				return defaultResult;
			}
		}

		final boolean myResult = new HistoryDao(repo).existUser(arg0.getUserId());

		LogHelper.customDirectoryPerformanceLog.debug("isUserDefined::" + (System.nanoTime() - start));

		return myResult;
	}

	@Override
	public boolean isUserInRole(UserReference user, Role role) {
		final Long start = System.nanoTime();

		final boolean result;

		if (role.isBuiltInAdministrator()) {

			if (customDirectory != null) {
				final Boolean isEbxAdminOutoftheBox = customDirectory.isUserInRole(user, role);

				if (isEbxAdminOutoftheBox != null) {
					LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: ADMIN." + isEbxAdminOutoftheBox + " EBX::" + (System.nanoTime() - start));
					return isEbxAdminOutoftheBox;
				}
			}

			final Adaptation userRecord = new HistoryDao(repo).lookupUser(user.getUserId());
			final Boolean isEbxAdmin = new AdaptationGetValueWrapper<Boolean>(userRecord).get(HistoryDao._user_isEbxAdmin);

			LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: ADMIN." + isEbxAdmin + " CUSTOM::" + (System.nanoTime() - start));

			return isEbxAdmin != null && isEbxAdmin;
		}

		if (role.isBuiltInReadOnly()) {
			LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: RO.true::" + (System.nanoTime() - start));

			if (customDirectory != null) {
				final Boolean isEbxReadonlyOutoftheBox = customDirectory.isUserInRole(user, role);

				if (isEbxReadonlyOutoftheBox != null) {
					LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: RO." + isEbxReadonlyOutoftheBox + " EBX::" + (System.nanoTime() - start));
					return isEbxReadonlyOutoftheBox;
				}
			}

			final Boolean isEbxReadonly = false;

			LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: RO." + isEbxReadonly + " CUSTOM::" + (System.nanoTime() - start));

			return isEbxReadonly;
		}

		LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: super.isUserInRole:: ...");

		if (customDirectory != null) {
			final Boolean isUserInRoleEbxOutoftheBox = customDirectory.isUserInRole(user, role);
			LogHelper.customDirectoryPerformanceLog.debug("isUserInRole:: super.isUserInRole::" + (System.nanoTime() - start));

			if (isUserInRoleEbxOutoftheBox) {
				return true;
			}
		}

		final String pk = String.format("%s|%s", user.getUserId(), role.getRoleName());
		final AdaptationTable table = new HistoryDao(repo).getUserRoleTable();

		if (table == null) {
			result = false;
		} else {
			final Adaptation userRole = table.lookupAdaptationByPrimaryKey(PrimaryKey.parseString(pk));
			result = userRole != null;
		}

		LogHelper.customDirectoryPerformanceLog.debug("isUserInRole::" + (System.nanoTime() - start));

		return result;
	}

	/**
	 * The profiles returned have some restrictions:
	 * <p>
	 * For defining permissions (see
	 * ProfileListContext.isForDefiningPermission()), the list must not contain
	 * the ADMINISTRATOR built-in role.
	 * </p>
	 * <p>
	 * For owning a data space, snapshot, or data set (see
	 * ProfileListContext.isForSelectingBranchOwner() and
	 * ProfileListContext.isForSelectingInstanceOwner()), the list must not
	 * contain the built-in role OWNER.
	 * </p>
	 * <p>
	 * For workflows (see ProfileListContext.isForWorkflow(), the list must not
	 * contain the built-in role OWNER.
	 * </p>
	 * <p>
	 * For defining views (see ProfileListContext.isForDefiningViews(), the list
	 * must not contain the built-in role OWNER.
	 * </p>
	 */
	@Override
	public List getProfiles(ProfileListContext aProfileContext) {
		// aProfileContext.isForDefiningPermission()
		// aProfileContext.isForDefiningViews()
		// aProfileContext.isForSelectingBranchOwner()
		// aProfileContext.isForSelectingInstanceOwner()
		// aProfileContext.isForWorkflow()

		final Long start = System.nanoTime();

		final List<Profile> profiles = new ArrayList<Profile>();
		profiles.addAll(getAllSpecificRoles());
		profiles.addAll(getAllUserReferences());

		if (aProfileContext.isForDefiningPermission()) {
			profiles.add(Profile.OWNER);
			profiles.add(Profile.EVERYONE);
		} else if (aProfileContext.isForSelectingBranchOwner() || aProfileContext.isForSelectingInstanceOwner()) {
			profiles.add(Profile.ADMINISTRATOR);
		} else if (aProfileContext.isForWorkflow()) {
			profiles.add(Profile.ADMINISTRATOR);
		} else {
			// isForDefiningViews()
			profiles.add(Profile.ADMINISTRATOR);
		}

		LogHelper.customDirectoryPerformanceLog.debug("getProfiles::" + (System.nanoTime() - start));

		return profiles;
	}

	@Override
	protected String getUserProfileURL(UIBuilder paramUIBuilder) {
		final Long start = System.nanoTime();

		final String result;

		final String defaultURL = super.getUserProfileURL(paramUIBuilder);

		if (defaultURL != null) {
			result = defaultURL;
		} else {
			final SessionImpl localSessionImpl = paramUIBuilder.getSession();

			if (localSessionImpl.isUserLoggedIn() == false) {
				result = null;
			} else {
				final UserReference localUserReference = localSessionImpl.getUserReference();

				final String aLogin = localUserReference.getUserId();
				final Adaptation userRecord = new HistoryDao(repo).lookupUser(aLogin);

				if (userRecord == null) {
					result = null;
				} else {
					final UIHttpManagerComponent localUIHttpManagerComponent = UIHttpManagerComponentBridge.create(localSessionImpl, paramUIBuilder);
					localUIHttpManagerComponent.select(userRecord.getHome().getKey(), userRecord.getContainer().getAdaptationName(),
							userRecord.toXPathExpression());
					localUIHttpManagerComponent.setScope(Scope.NODE);
					localUIHttpManagerComponent.setRedirectionURI(UICSSCatalog.getWindowModalRefreshParentUrl(paramUIBuilder));
					localUIHttpManagerComponent.setCloseButtonSpec(UIHttpManagerComponent.CloseButtonSpec.CROSS);

					result = localUIHttpManagerComponent.getURIWithParameters();
				}
			}
		}

		LogHelper.customDirectoryPerformanceLog.debug("getUserProfileURL::" + (System.nanoTime() - start));

		return result;
	}

	@Override
	public UserReference authenticateUserFromArray(final Object[] args) {
		if (args != null && args[0] != null && args[0].equals("ScriptTaskBean_MergeWithMakerIdentity") && args[1] != null) {
			final UserReference user = (UserReference) args[1];
			return user;
		}

		return null;
	}

	private RestProperties getRestProperties(){
		BasicTextEncryptor bte = new BasicTextEncryptor();
		bte.setPassword("WJ~%$(sMJKbVA2m!");
		Map<String,Object> ebxRestProperties = (Map<String,Object>)((Map<String,Object>)((Map<String,Object>)getPropertiesMap().get("keysight")).get("rest")).get("orchestra");
		RestProperties restProperties = new RestProperties();
		Orchestra orchestra = new Orchestra();
		orchestra.setHost(String.valueOf(ebxRestProperties.get("host")));
		orchestra.setSsl(String.valueOf(ebxRestProperties.get("ssl")));
		orchestra.setUsername(String.valueOf(ebxRestProperties.get("username")));
		orchestra.setPassword(bte.decrypt(String.valueOf(ebxRestProperties.get("password")).replaceFirst("ENC\\(","").replace(")","")));
		orchestra.setPort(String.valueOf(ebxRestProperties.get("port")));
		orchestra.setBaseURI(String.valueOf(ebxRestProperties.get("baseURI")));
		orchestra.setVersion(String.valueOf(ebxRestProperties.get("version")));
		orchestra.setConnectTimeout(5000);
		orchestra.setReadTimeout(70000);
		restProperties.setOrchestra(orchestra);
		return restProperties;
	}

	private Map<String,Object> getPropertiesMap(){
		Map<String,Object> result = null;
		Yaml yaml = new Yaml();
		if(propertiesCache!=null){
			result = propertiesCache;
		}else {
			String location = System.getProperty("spring.config.location");
			String fileName = System.getProperty("spring.config.name");
			String profile = System.getProperty("spring.profiles.active");
			String filePath = location + fileName + "-" + profile + ".yml";
			InputStream ios = null;
			try {
				ios = new FileInputStream(new File(filePath));
				result = (Map<String, Object>) yaml.load(ios);
				propertiesCache = result;
			} catch (FileNotFoundException e) {
				LogHelper.customDirectoryPerformanceLog.error("Error reading EBX REST config from external file " + e.getMessage());
			}
		}
		if(result==null){
			throw new RuntimeException("Error reading EBX REST config from external file");
		}
		return result;
	}

}

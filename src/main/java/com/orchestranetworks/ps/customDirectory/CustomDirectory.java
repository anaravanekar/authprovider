package com.orchestranetworks.ps.customDirectory;

import com.onwbp.adaptation.AdaptationHome;
import com.orchestranetworks.service.Profile;
import com.orchestranetworks.service.UserReference;
import com.orchestranetworks.service.directory.AuthenticationException;
import com.orchestranetworks.service.directory.Directory;
import com.orchestranetworks.service.directory.DirectoryDefault;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Mickael GERMEMONT
 * 
 */
public class CustomDirectory extends DirectoryDefault {

	protected CustomDirectory(final AdaptationHome arg0) {
		super(arg0);
	}

	UserReference become(final Directory dir, final UserReference user, final String becomeInput) {
		final UserReference userResult;

		final String uname = user.getUserId();

		// User is defined and authenticated
		final String become = becomeInput;

		LogHelper.customDirectoryLog.debug(String.format("%b is user %s admin", dir.isUserInRole(user, Profile.ADMINISTRATOR), user));
		LogHelper.customDirectoryLog.debug(String.format("become %s", become));

		if (become != null && (dir.isUserInRole(user, Profile.ADMINISTRATOR))) {
			final UserReference beUser = UserReference.forUser(become);

			if (dir.isUserDefined(beUser) == false) {
				LogHelper.customDirectoryLog.debug(String.format("authenticateUserFromHttpRequest: become-notallowed-unknownuser"));

				LogHelper.customDirectoryLog.info("NOT Allowing user '" + uname + "' to become user '" + become+ "' because become user is unknown");
				userResult = null;
			} else {
				if (dir.isUserInRole(user, Profile.ADMINISTRATOR) == false&& dir.isUserInRole(beUser, Profile.ADMINISTRATOR)) {
					LogHelper.customDirectoryLog.debug(String.format("authenticateUserFromHttpRequest: become-notallowed-wantstobeadminbutisnotadmin"));

					// if user is not admin and tries to be admin, then reject that operation
					LogHelper.customDirectoryLog.info("NOT Allowing user '" + uname + "' to become user '" + become+ "' because that is an EBX Administrator this would escalate his priviledges !");
					userResult = null;
				} else {
					LogHelper.customDirectoryLog.debug(String.format("authenticateUserFromHttpRequest: become-allowed"));
					LogHelper.customDirectoryLog.info("Allowing user '" + uname + "' to become user '" + become + "'");
					userResult = beUser;
				}
			}
		} else {
			LogHelper.customDirectoryLog.info(String.format("authenticateUserFromHttpRequest: become-no"));
			userResult = null;
		}

		return userResult;
	}

	UserReference sso(final HttpServletRequest req) {

		final UserReference user;

		if (req.getRemoteUser() != null) {
			// SSO feature
			LogHelper.customDirectoryLog.debug(String.format("authenticateUserFromHttpRequest: AUTH-SSO"));

			String uname = req.getRemoteUser();
			if ((uname != null) && (!"".equals(uname))) {
				if (uname.contains("\\")) {
					uname = uname.split("\\\\")[1];
				}
				
				return UserReference.forUser(uname.toUpperCase());
			}
			
			return null;

		} else {
			LogHelper.customDirectoryLog.debug(String.format("authenticateUserFromHttpRequest: AUTH-DEFAULT"));
			user = super.authenticateUserFromHttpRequest(req);
		}

		return user;
	}

	@Override
	public UserReference authenticateUserFromHttpRequest(final HttpServletRequest req) throws AuthenticationException {
		LogHelper.customDirectoryLog.debug(String.format("customdir.authenticateUserFromHttpRequest[req]..."));

		final UserReference user = sso(req);

		if (user == null) {
			LogHelper.customDirectoryLog.info("unknown login request");
			return null;
		}

		final UserReference became = become(this, user, req.getParameter("become"));
		if (became != null) {
			return became;
		}

		return user;
	}
}

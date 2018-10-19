package com.orchestranetworks.ps.customDirectory;

import com.orchestranetworks.service.directory.AuthenticationException;
import com.unboundid.ldap.sdk.*;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLSocketFactory;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.util.*;
import java.util.jar.Attributes;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class LdapClientUnboundId {

    protected Properties props = null;

    protected static final String PROPERTY_HEADER = "ebx.directory.ldap.";
    protected static final String HOST = "host";
    protected static final String PORT = "port";
    protected static final String USE_SSL = "useSSL";
    protected static final String PATH = "path";
    protected static final String BASE_DN = "baseDN";
    protected static final String BIND_DN = "bindDN";
    protected static final String USER_SEARCH = "search";
    protected static final String REQ_TOLOGIN_MEMBERSHIP_BASE = "requiredToLogin.membershipBase";
    protected static final String REQ_TOLOGIN_ROLE = "requiredToLogin.role";
    protected static final String REQ_TOLOGIN_MEMBERSHIP_FILTER = "requiredToLogin.membershipFilter";

    protected String useSsl = null;
    protected String host = null;
    protected String port = null;
    protected String ldapPath = null;
    protected String baseDN = null;
    protected String bindDN = null;
    protected String userSearch = null;
    protected String reqLogin_membershipBase = null;
    protected String reqLogin_membershipFilter = null;
    
    protected SearchResultEntry searchLdap(final String username, final String password) {
        LDAPConnection ldapConnection = null;
        MessageFormat bindDNFormat = ldapFormat(BIND_DN);
        String bindDN = bindDNFormat.format(new Object[] { username });
        String filterString = ldapFormat(REQ_TOLOGIN_MEMBERSHIP_FILTER).format(new Object[] { username });
        LogHelper.customDirectoryLog.debug(String.format("CONNECTING LDAP with SSL=%s,host=%s,port=%s,bindDN=%s",useSsl,host,port,bindDN));
        try {
            if ("true".equalsIgnoreCase(useSsl)) {
                SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
                SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
                ldapConnection = new LDAPConnection(sslSocketFactory, host, Integer.valueOf(port), bindDN, password);
            } else {
                ldapConnection = new LDAPConnection(host, Integer.valueOf(port), bindDN, password);
            }
            LogHelper.customDirectoryLog.debug(String.format("CONNECTED connection=%s", ldapConnection.hashCode()));
        }catch (LDAPException ldapException){
            throw new RuntimeException(String.format("LDAP authentication failed (Error code = %s)",String.valueOf(ldapException.getResultCode())),ldapException);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException("Unexpected error occurred while authenticating with LDAP server. Please contact your administrator.",ex);
        }
        Filter filter = null;
        try {
            filter = Filter.create(filterString);
            SearchRequest searchRequest = new SearchRequest(reqLogin_membershipBase, SearchScope.SUB, filter, "sAMAccountName", "givenName", "sn", "mail", "memberOf");
            LogHelper.customDirectoryLog.debug(String.format("SEARCHING with base=%s, filter=%s",reqLogin_membershipBase,filter));
            SearchResult searchResult = ldapConnection.search(searchRequest);
            LogHelper.customDirectoryLog.debug(String.format("RESULT CODE=%s",searchResult.getResultCode()));
            ldapConnection.close();
            LogHelper.customDirectoryLog.debug(String.format("CLOSED connection=%s",ldapConnection.hashCode()));
            if(searchResult.getResultCode().equals(ResultCode.SUCCESS) && searchResult.getEntryCount()>0){
                return searchResult.getSearchEntries().get(0);
            }else{
                throw new RuntimeException("You are not authorized to access this system. Please contact your administrator.");
            }
        }catch (LDAPException e) {
            throw new RuntimeException("Unexpected error occurred while authenticating with LDAP server. Please contact your administrator.",e);
        }
    }

    protected MessageFormat ldapFormat(final String key) {
        String val = this.props.getProperty(PROPERTY_HEADER + key);
        if(null != val){
            final String value = val.replace("\"", "");
            return new MessageFormat(value);
        }
        return null;
    }

    protected void updateDirProperties(Properties p) {
        LogHelper.customDirectoryLog.debug("LOADING LDAP PROPERTIES...");
        this.props = p;
        updateDirProperties();
    }

    protected void updateDirProperties() {
        useSsl = ldapProp(USE_SSL);
        host = ldapProp(HOST);
        port = ldapProp(PORT);
        ldapPath = ldapProp(PATH);
        baseDN = ldapProp(BASE_DN);
        bindDN = ldapProp(BIND_DN);

        reqLogin_membershipBase = ldapProp(REQ_TOLOGIN_MEMBERSHIP_BASE);
        reqLogin_membershipFilter = ldapProp(REQ_TOLOGIN_MEMBERSHIP_FILTER);

        userSearch = ldapProp(USER_SEARCH);
    }

    protected String ldapProp(final String key) {
        String val = this.props.getProperty(PROPERTY_HEADER + key);
        if (null != val){
            final String value = val.replace("\"", "");
            return value;
        }
        return null;
    }

    protected LdapName ldapNameProp(final String key) {
        String val = this.props.getProperty(PROPERTY_HEADER + key);
        if(null != val){
            final String value = val.replace("\"", "");

            LdapName name = null;
            try {
                name = new LdapName(value);

                return name;
            } catch (Exception e) {
                //logger.severe("Invalid name for LDAP name  " + key+ ".  Be sure to double any \\ characters.");
            }
        }
        return null;
    }
}

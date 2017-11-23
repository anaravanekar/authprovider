package com.keysight.authprovider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keysight.authprovider.custom.ExternalDirectory;
import com.keysight.authprovider.custom.LdapActiveDirectory;
import com.keysight.authprovider.mdmcustom.config.properties.RestProperties;
import com.keysight.authprovider.mdmcustom.config.properties.ws.Orchestra;
import com.keysight.authprovider.mdmcustom.model.*;
import com.keysight.authprovider.mdmcustom.rest.client.OrchestraRestClient;

import java.io.IOException;
import java.util.*;
import java.util.AbstractMap.SimpleEntry;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.ws.rs.core.Response;

public class TestActiveDirectory {

	static DirContext ldapContext;
	public static void main (String[] args) throws NamingException
	{
		try
		{
			System.out.println("Test Active Directory");

			Hashtable<String, String> ldapEnv = new Hashtable<String, String>(11);
			ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			ldapEnv.put(Context.PROVIDER_URL,  "ldaps://10.10.10.86:636");
			ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
			ldapEnv.put(Context.SECURITY_PRINCIPAL, "CN=user,CN=Users,DC=astserene,DC=local");
			ldapEnv.put(Context.SECURITY_CREDENTIALS, "serene*123");
			
			ldapContext = new InitialDirContext(ldapEnv);

			// Create the search controls         
			SearchControls searchCtls = new SearchControls();

			//Specify the attributes to return
			String returnedAtts[]={"sn","givenName", "samAccountName"};
			searchCtls.setReturningAttributes(returnedAtts);

			//Specify the search scope
			searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

			//specify the LDAP search filter
			//String searchFilter = "(&(objectClass=user)(samAccountName=user1))";
			String searchFilter  = "(&(objectClass=user)(sAMAccountName=user1)(memberOf=CN=Datasteward,CN=Builtin,DC=astserene,DC=local))";
			//Specify the Base for the search
			//String searchBase = "DC=astserene,DC=local";
			String searchBase = "DC=astserene,DC=local";
			//initialize counter to total the results
			int totalResults = 0;

			// Search for objects using the filter
			NamingEnumeration<SearchResult> answer = ldapContext.search(searchBase, searchFilter, searchCtls);

			//Loop through the search results
			while (answer.hasMoreElements())
			{
				SearchResult sr = (SearchResult)answer.next();

				totalResults++;

				System.out.println(">>>" + sr.getName());
				Attributes attrs = sr.getAttributes();
				System.out.println(">>>>>>" + attrs.get("samAccountName"));
			}

			System.out.println("Total results: " + totalResults);
			ldapContext.close();
		}
		catch (Exception e)
		{
			System.out.println(" Search error: " + e);
			e.printStackTrace();
			System.exit(-1);
		}
	}
/*	public static void main(String[] args) {
		String userId = "user1";
		OrchestraObjectList orchestraObjectList = new OrchestraObjectList();
		List<OrchestraObject> rows = new ArrayList<>();
		HashMap<String,String> ebxRoles = new HashMap<>();

		OrchestraRestClient orchestraRestClient = new OrchestraRestClient(getRestProperties());
		OrchestraObjectListResponse orchestraObjectListResponse = null;
		try {
			orchestraObjectListResponse = orchestraRestClient.get("Bebx-directory","ebx-directory","directory/roles",null);
			if(orchestraObjectListResponse!=null && orchestraObjectListResponse.getRows() != null && !orchestraObjectListResponse.getRows().isEmpty()) {
				List<OrchestraObjectResponse> resultRows = orchestraObjectListResponse.getRows();
				for(OrchestraObjectResponse response:resultRows){
					String roleName = response.getContent().get("name").getContent().toString();
					//ebxRoles.put("CN="+roleName+",CN=Users,DC=KEYSIGHT,DC=COM",roleName);
					ebxRoles.put("CN="+roleName+",CN=Builtin,DC=astserene,DC=local",roleName);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("size="+orchestraObjectListResponse.getRows().size());
		ExternalDirectory extDir = new LdapActiveDirectory();
		ArrayList<SimpleEntry<String, String>> res = extDir.getUserInfo("user1|serene*123");
		for(SimpleEntry entry:res){
			if("memberOf".equals(entry.getKey())){
				if(ebxRoles.get(entry.getValue())!=null) {
					OrchestraObject orchestraObject = new OrchestraObject();
					Map<String,OrchestraContent> content = new HashMap<String, OrchestraContent>();
					content.put("user",new OrchestraContent(userId));
					content.put("role",new OrchestraContent(ebxRoles.get(entry.getValue())));
					orchestraObject.setContent(content);
					rows.add(orchestraObject);
				}
			}
		}
		orchestraObjectList.setRows(rows);
		try {
			Map<String, String> parameters = new HashMap<String, String>();
			parameters.put("updateOrInsert", "true");
			ObjectMapper mapper = new ObjectMapper();
			System.out.println("req:"+mapper.writeValueAsString(orchestraObjectList));
			Response response = orchestraRestClient.insert("Bebx-directory","ebx-directory","directory/usersRoles",orchestraObjectList,parameters);
			System.out.println("status:"+response.getStatus());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}*/
	private static RestProperties getRestProperties(){
		RestProperties restProperties = new RestProperties();
		Orchestra orchestra = new Orchestra();
		orchestra.setHost("localhost");
		orchestra.setSsl("false");
		orchestra.setUsername("admin");
		orchestra.setPassword("Serene*123");
		orchestra.setPort("8080");
		orchestra.setBaseURI("/ebx-dataservices/rest/data/");
		orchestra.setVersion("v1");
		orchestra.setConnectTimeout(5000);
		orchestra.setReadTimeout(70000);
		restProperties.setOrchestra(orchestra);
		return restProperties;
	}
}

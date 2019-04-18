package com.nulli.openam.plugins;

import java.security.Principal;

import javax.security.auth.Subject;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;

public class MockConnection {

	public void setDBConnection(NeoUniversalCondition testClass){
    	String NEO_DB_URL = "bolt://localhost:7687";
        String NEO_DB_USERNAME = "neo4j";
        String NEO_DB_PASSWORD = "Welcome1";
        String NEO_ALLOW_RESULT = "true";
        String NEO_DENY_RESULT = "false"; 
    	testClass.setDbURL(NEO_DB_URL);
    	testClass.setDbUsername(NEO_DB_USERNAME);
    	testClass.setDbPassword(NEO_DB_PASSWORD);
    	testClass.setAllowCypherResult(NEO_ALLOW_RESULT);
    	testClass.setDenyCypherResult(NEO_DENY_RESULT);
		
	}
	
	public void setSubject(Subject s){
		Principal p = new MockPrincipal("testUser");
		s.getPrincipals().add(p);
		SSOToken token = new MockToken();
		try {
			token.setProperty("password","test1234");
		} catch (SSOException e) {
			e.printStackTrace();
		}
		s.getPrivateCredentials().add(token);		
	}
}

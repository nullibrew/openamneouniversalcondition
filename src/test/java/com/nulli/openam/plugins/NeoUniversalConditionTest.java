package com.nulli.openam.plugins;


import com.iplanet.log.ConnectionException;
import com.sun.identity.entitlement.ConditionDecision;
import com.sun.identity.entitlement.EntitlementException;
import javax.security.auth.Subject;

import org.neo4j.driver.v1.exceptions.ClientException;
import org.testng.Assert;
import org.testng.TestException;
import org.testng.annotations.Test;

public class NeoUniversalConditionTest {
    NeoUniversalCondition testClass;
    Subject s;
    
    public NeoUniversalConditionTest(){
    	testClass = new NeoUniversalCondition();
		s = new Subject();
    }
    
    @Test(expectedExceptions = EntitlementException.class)
    public void validate() throws EntitlementException{
    	MockConnection con = new MockConnection();
		con.setDBConnection(testClass);
		con.setSubject(s);
    	testClass.setCypherQuery("");
    	testClass.validate();
    }
    
    @Test
    public void getState(){
    	MockConnection con = new MockConnection();
		con.setDBConnection(testClass);
		con.setSubject(s);
    	Assert.assertNotNull(testClass.getState());
    }
    
    @Test
    public void neoQueryEmptyParams() {
    	try {
    		MockConnection con = new MockConnection();
    		con.setDBConnection(testClass);
    		con.setSubject(s);
			String NEO_CYPHER_QUERY = "optional match p=(u:User {name: 'George Clinton'}) with case p when null then 'false' else 'true' end as result return result";
			String NEO_QUERY_PARAMS = "";
	    	testClass.setCypherQuery(NEO_CYPHER_QUERY);
	    	testClass.setParamsJson(NEO_QUERY_PARAMS);
			ConditionDecision testCondition = testClass.evaluate("/", s, "", null);
			Assert.assertTrue(testCondition.isSatisfied());
		} catch (EntitlementException e) {
			e.printStackTrace();
		}
       
    }
 
    @Test
    public void neoQueryProperParams() {
    	try {
    		MockConnection con = new MockConnection();
    		con.setDBConnection(testClass);
    		con.setSubject(s);
			String NEO_CYPHER_QUERY = "optional match p=(u:User {name: {name}}) with case p when null then 'false' else 'true' end as result return result";
			String NEO_QUERY_PARAMS = "{'name': 'test'}";
	    	testClass.setCypherQuery(NEO_CYPHER_QUERY);
	    	testClass.setParamsJson(NEO_QUERY_PARAMS);
			ConditionDecision testCondition = testClass.evaluate("/", s, "", null);
			Assert.assertFalse(testCondition.isSatisfied());
		} catch (EntitlementException e) {
			e.printStackTrace();
		}
       
    }
    
    @Test
    public void neoQueryNullParams() {
    	try {
    		MockConnection con = new MockConnection();
    		con.setDBConnection(testClass);
    		con.setSubject(s);
			String NEO_CYPHER_QUERY = "optional match p=(u:User {name: 'George Clinton'}) with case p when null then 'false' else 'true' end as result return result";
			String NEO_QUERY_PARAMS = null;
	    	testClass.setCypherQuery(NEO_CYPHER_QUERY);
	    	testClass.setParamsJson(NEO_QUERY_PARAMS);
			ConditionDecision testCondition = testClass.evaluate("/", s, "", null);
			Assert.assertTrue(testCondition.isSatisfied());
		} catch (EntitlementException e) {
			e.printStackTrace();
		}
       
    }
   
    @Test
    public void neoQueryNotMatchedParams() {
    	try {
    		MockConnection con = new MockConnection();
    		con.setDBConnection(testClass);
    		con.setSubject(s);
			String NEO_CYPHER_QUERY = "optional match p=(u:User {name: {name}}) with case p when null then 'false' else 'true' end as result return result";
			String NEO_QUERY_PARAMS = "";
	    	testClass.setCypherQuery(NEO_CYPHER_QUERY);
	    	testClass.setParamsJson(NEO_QUERY_PARAMS);
			ConditionDecision testCondition = testClass.evaluate("/", s, "", null);
			Assert.assertFalse(testCondition.isSatisfied());
		} catch (EntitlementException e) {
			e.printStackTrace();
		}
       
    }
    
}

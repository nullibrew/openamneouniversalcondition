/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015 Nulli Secundus Inc.
 */


package com.nulli.openam.plugins;

import com.iplanet.log.ConnectionException;


import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.entitlement.ConditionDecision;
import com.sun.identity.entitlement.EntitlementCondition;
import com.sun.identity.entitlement.EntitlementException;

import static com.sun.identity.entitlement.EntitlementException.PROPERTY_VALUE_NOT_DEFINED;

import com.sun.identity.entitlement.PrivilegeManager;
import com.sun.identity.shared.debug.Debug;

import java.lang.reflect.InvocationTargetException;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.net.URI;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import org.forgerock.openam.core.CoreWrapper;

import static org.forgerock.openam.entitlement.conditions.environment.ConditionConstants.*;

import org.forgerock.openam.entitlement.conditions.environment.EntitlementCoreWrapper;
import org.forgerock.openam.utils.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.neo4j.driver.v1.*;
import org.neo4j.driver.internal.InternalDriver;
import org.neo4j.driver.v1.exceptions.*;
import org.neo4j.driver.v1.exceptions.SecurityException;

/**
 * Neo4j-Universal Policy Environmental Condition Plugin for AM
 *
 * An implementation of an
 * {@link com.sun.identity.entitlement.EntitlementCondition} that will check
 * whether the principal meets condition based on a parameterized cypher 
 * query against a Neo4j graph dabatase.
 *
 * @since 12.0.0
 * @author Hadi Ahmadi, Seyed Hossein Ahmadinejad
 */
public class NeoUniversalCondition implements EntitlementCondition {

    private static final String NEO_DB_URL = "neoDbURL";
    private static final String NEO_DB_USERNAME = "neoDbUsername";
    private static final String NEO_DB_PASSWORD = "neoDbPassword";
    private static final String NEO_CYPHER_QUERY = "neoCypherQuery";
    private static final String NEO_QUERY_PARAMS = "neoQueryParams";
    private static final String NEO_INLINE_PARAMS = "neoInlineParams";
    // TODO Add policy advice support
    //private static final String NEO_ADVICE_MAP = "neoAdviceMap";
    private static final String NEO_ALLOW_RESULT = "neoAllowResult";
    private static final String NEO_DENY_RESULT = "neoDenyResult";
    private static final int QUERY_EXECUTION_MAX_RETRY = 2;
    private final CoreWrapper coreWrapper;
    private final Debug debug;
    private final EntitlementCoreWrapper entitlementCoreWrapper;
    private Driver driver;

    private String dbURL = null;
    private String dbUsername = null;
    private String dbPassword = null;
    private String cypherQuery = null;
    private String paramsJson = null;
    private String inlineParams = null;
    private String allowCypherResult = null;
    private String denyCypherResult = null;
    private String displayType;

    /**
     * Constructs a new NeoUniversalCondition instance.
     */
    public NeoUniversalCondition() {
        this(PrivilegeManager.debug, new CoreWrapper(), new EntitlementCoreWrapper());
    }

    /**
     * Constructs a new NeoUniversalCondition instance.
     *
     * @param debug A Debug instance.
     * @param coreWrapper An instance of the CoreWrapper.
     * @param entitlementCoreWrapper An instance of the EntitlementCoreWrapper.
     */
    NeoUniversalCondition(Debug debug, CoreWrapper coreWrapper, EntitlementCoreWrapper entitlementCoreWrapper) {
        this.debug = debug;
        this.coreWrapper = coreWrapper;
        this.entitlementCoreWrapper = entitlementCoreWrapper;
    }

    private static String getInitStringValue(Set<String> set) {
        return ((set == null) || set.isEmpty()) ? "" : set.iterator().next();
    }

    private static String getStringValue(Set<String> set) {
        return ((set == null) || set.isEmpty()) ? null : set.iterator().next();
    }

    @Override
    public String getDisplayType() {
        return displayType;
    }

    @Override
    public void setDisplayType(String displayType) {
        this.displayType = displayType;
    }

    public void setDbURL(String dbURL) {
        this.dbURL = dbURL;
    }

    public String getDbURL() {
        return dbURL;
    }

    public void setDbUsername(String dbUsername) {
        this.dbUsername = dbUsername;
    }

    public String getDbUsername() {
        return dbUsername;
    }

    public void setDbPassword(String dbPassword) {
        this.dbPassword = dbPassword;
    }

    public String getDbPassword() {
        return dbPassword;
    }

    public void setCypherQuery(String cypherQuery) {
        this.cypherQuery = cypherQuery;
    }

    public String getCypherQuery() {
        return cypherQuery;
    }

    public void setParamsJson(String paramsJson) {
        this.paramsJson = paramsJson;
    }

    public String getParamsJson() {
        return paramsJson;
    }

    public void setInlineParams(String inlineParams) {
        this.inlineParams = inlineParams;
    }

    public String getInlineParams() {
        return inlineParams;
    }

    public void setAllowCypherResult(String allowCypherResult) {
        this.allowCypherResult = allowCypherResult;
    }

    public String getAllowCypherResult() {
        return allowCypherResult;
    }

    public void setDenyCypherResult(String denyCypherResult) {
        this.denyCypherResult = denyCypherResult;
    }

    public String getDenyCypherResult() {
        return denyCypherResult;
    }

    @Override
    public void init(Map<String, Set<String>> map) {
        for (String key : map.keySet()) {
            if (key.equalsIgnoreCase(NEO_DB_URL)) {
                setDbURL(getInitStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_DB_USERNAME)) {
                setDbUsername(getInitStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_DB_PASSWORD)) {
                setDbPassword(getInitStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_CYPHER_QUERY)) {
                setCypherQuery(getInitStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_QUERY_PARAMS)) {
                setParamsJson(getStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_INLINE_PARAMS)) {
                setInlineParams(getStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_ALLOW_RESULT)) {
                setAllowCypherResult(getStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_DENY_RESULT)) {
                setDenyCypherResult(getStringValue(map.get(key)));
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getState() {
        JSONObject jo = new JSONObject();
        try {
            jo.put(NEO_DB_URL, dbURL);
            jo.put(NEO_DB_USERNAME, dbUsername);
            jo.put(NEO_DB_PASSWORD, dbPassword);
            jo.put(NEO_CYPHER_QUERY, cypherQuery);
            jo.put(NEO_QUERY_PARAMS, paramsJson);
            jo.put(NEO_INLINE_PARAMS, inlineParams);
            jo.put(NEO_ALLOW_RESULT, allowCypherResult);
            jo.put(NEO_DENY_RESULT, denyCypherResult);
        } catch (JSONException ex) {
            debug.error("AM Neo4j Policy Plugin: failed to get state - " + ex.getMessage());
        }
        return jo.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setState(String state) {
        try {
            JSONObject jo = new JSONObject(state);

            // TODO check realm from a field!!!
            // String realm = coreWrapper.getRealmFromRealmQualifiedData(paramsJson);
            // realmEmpty = StringUtils.isBlank(realm);

            // TODO sanitize
            if (jo.has(NEO_DB_URL)) {
                setDbURL(jo.getString(NEO_DB_URL));
            }
            if (jo.has(NEO_DB_USERNAME)) {
                setDbUsername(jo.getString(NEO_DB_USERNAME));
            }
            if (jo.has(NEO_DB_PASSWORD)) {
                setDbPassword(jo.getString(NEO_DB_PASSWORD));
            }
            if (jo.has(NEO_CYPHER_QUERY)) {
                setCypherQuery(jo.getString(NEO_CYPHER_QUERY));
            }
            if (jo.has(NEO_QUERY_PARAMS)) {
                setParamsJson(jo.getString(NEO_QUERY_PARAMS));
            }
            if (jo.has(NEO_INLINE_PARAMS)) {
                setInlineParams(jo.getString(NEO_INLINE_PARAMS));
            }
            if (jo.has(NEO_ALLOW_RESULT)) {
                setAllowCypherResult(jo.getString(NEO_ALLOW_RESULT));
            }
            if (jo.has(NEO_DENY_RESULT)) {
                setDenyCypherResult(jo.getString(NEO_DENY_RESULT));
            }

        } catch (JSONException e) {
            debug.error("AM Neo4j Policy Plugin: failed to set state - " + e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("deprecation")
    @Override
    public ConditionDecision evaluate(String realm, Subject subject, String resourceName, Map<String, Set<String>> env)
            throws EntitlementException {

        Map<String, Set<String>> advices = new HashMap<>();

        if (!subject.getPrincipals().isEmpty()) {
            try {
                String cypherResult;
                HashMap<String, Object> params = sanitizeParams(paramsJson, realm, subject, resourceName, env);
                cypherResult = neoQuery( (inlineParams == null) || inlineParams.isEmpty() ? cypherQuery : replaceInlineParams(cypherQuery, inlineParams.split(","), params), params, 1);
                if (cypherResult == null) {
                    throw new ConnectionException("Error response received from the Graph DB while querying NeoClientType!");
                }
                if (cypherResult.equalsIgnoreCase(allowCypherResult)) {
                    return new ConditionDecision(true, advices);
                } else if (cypherResult.equalsIgnoreCase(denyCypherResult)) {
                    return new ConditionDecision(false, advices);
                }
            }
            catch (ConnectionException ex) {
                debug.error("AM Neo4j Policy Plugin: Connection to Neo4j failed - " + ex.getMessage());
            }
            catch (JSONException ex) {
                debug.error("AM Neo4j Policy Plugin:Cannot parse parameters in the policy evaluation request body - " + ex.getMessage());
            }
        }

        return new ConditionDecision(false, advices); // This is a deny
    }

    @Override
    public void validate() throws EntitlementException {
        if (StringUtils.isBlank(cypherQuery)) {
            throw new EntitlementException(PROPERTY_VALUE_NOT_DEFINED, NEO_CYPHER_QUERY);
        }
    }

    /**
     * @param cypherQuery
     * @param inlineParams
     * @param params
     * @return cypher query where parameters in inlineParams have been replaced with their values from params
     * @throws JSONException
     */
    private String replaceInlineParams(String cypherQuery, String[] inlineParams, HashMap<String, Object> params) throws JSONException {
        for (String inlineParam: inlineParams) {
            String paramValue = "'" + params.get(inlineParam).toString() + "'";
            cypherQuery = cypherQuery.replace("{" + inlineParam + "}", paramValue).replace("$" + inlineParam, paramValue);
        }
        return cypherQuery;
    }

    private HashMap<String, Object> sanitizeParams(String params, String realm, Subject subject, String resourceName, Map<String, Set<String>> env) throws EntitlementException {
        JSONObject jsonParams = null;
        HashMap<String, Object> sanitizedParams = null;
        boolean requestHasParams = false;
        Map<String, String> reqParamMap = new LinkedHashMap<>();

        if (resourceName.split("\\?").length > 1) {
            requestHasParams = true;
            String urlQuery = resourceName.split("\\?")[1];
            String[] urlParams = urlQuery.split("&");
            for (String param : urlParams) {
                int idx = param.indexOf("=");
                reqParamMap.put(param.substring(0, idx), param.substring(idx + 1));
            }
        }

        try {
            if ((params != null) && (!params.isEmpty())) {
                sanitizedParams = new HashMap<>();
                jsonParams = new JSONObject(params);
                @SuppressWarnings("unchecked")
                Iterator<String> paramItr = jsonParams.keys();

                while (paramItr.hasNext()) {
                    String paramKey = paramItr.next();
                    String paramVal = jsonParams.get(paramKey).toString();
                    if (paramVal.startsWith("__")) {
                        if (paramVal.equals("__userId")) {
                            if (subject.getPrincipals().isEmpty()) {
                                throw new EntitlementException(
                                        EntitlementException.CONDITION_EVALUATION_FAILED,
                                        "could not find userId (required) from subject");
                            } else {
                                String userID = getUserId(subject);
                                userID = (String) javax.naming.ldap.Rdn.unescapeValue(userID);
                                paramVal = userID;
                            }
                        } else if (paramVal.equals("__resourceName")) {
                            paramVal = resourceName;
                        } else if (paramVal.equals("__realm")) {
                            paramVal = realm;
                        } else if (paramVal.startsWith("__env__")) {
                            String envParam = paramVal.substring(7);
                            String envParamVal = envMapStringify(envParam, env.get(envParam));x
                            paramVal = envParamVal;
                        } else if (paramVal.startsWith("__token")) {
                            if (subject.getPrivateCredentials().isEmpty()) {
                                throw new EntitlementException(
                                        EntitlementException.CONDITION_EVALUATION_FAILED,
                                        "could not find token (required) from subject");
                            }
                            SSOToken token = (SSOToken) subject.getPrivateCredentials().iterator().next();
                            if (paramVal.startsWith("__token__")) {
                                String tokenProp = paramVal.substring(7);
                                String tokenPropVal = token.getProperty(tokenProp);
                                paramVal = tokenPropVal;
                            } else if (paramVal.startsWith("__token.")) {
                                String tokenMethod = paramVal.substring(6);
                                java.lang.reflect.Method method = token.getClass().getMethod(tokenMethod);
                                String methodRet = method.invoke(token).toString();
                                paramVal = methodRet;
                            }
                        } else if (paramVal.startsWith("__req__") && requestHasParams) {
                            String reqParam = paramVal.substring(7);
                            if (reqParamMap.containsKey(reqParam)) {
                                String reqParamVal = reqParamMap.get(reqParam);
                                paramVal = reqParamVal;
                            }
                        }
                    }
                    sanitizedParams.put(paramKey, paramVal);
                }
            }
        } catch (JSONException | SSOException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException  ex) {
            debug.error("AM Neo4j Policy Plugin: " + ex.getMessage());
        }
        return sanitizedParams;
    }

    public String getRequestIp(Map<String, Set<String>> env) {
        String ip = null;
        final Object requestIp = env.get(REQUEST_IP);

        if (requestIp instanceof Set) {
            @SuppressWarnings("unchecked")
            Set<String> requestIpSet = (Set<String>) requestIp;
            if (!requestIpSet.isEmpty()) {
                if (requestIpSet.size() > 1) {
                    debug.warning("AM Neo4j Policy Plugin: Environment map {0} cardinality > 1. Using first from: {1}",
                            REQUEST_IP, requestIpSet);
                }
                ip = requestIpSet.iterator().next();
            }
        } else if (requestIp instanceof String) {
            ip = (String) requestIp;
        }

        if (StringUtils.isBlank(ip)) {
            debug.warning("AM Neo4j Policy Plugin: Environment map {0} is null or empty", REQUEST_IP);
        }
        return ip;
    }


    private String neoQuery(String statement, HashMap<String, Object> params, int retry){
        // TODO Auto-generated method stub
        driver = getDriver();
        Session session = null;
        StatementResult result;

        try {session = driver.session(AccessMode.READ);
            if(params != null)
                result = session.run(statement, params);
            else
                result = session.run(statement);
            List<String> results = new ArrayList<>();
            while ( result.hasNext() )
            {
                Record record = result.next();
                for ( String key : record.keys() )
                    results.add(record.get(key).asString());
            }
            if(!results.isEmpty()){
                return results.get(0);
            }
        } catch(NoSuchRecordException ne){
            debug.error("AM Neo4j Policy Plugin: No records returned - " + ne.getMessage());
        } catch(Neo4jException | IllegalStateException e){
            debug.message("Error while connecting to neo4j: " + e.getMessage());
            debug.error("AM Neo4j Policy Plugin: Error while connecting to neo4j:  - " + e.getMessage());
            if (retry < this.QUERY_EXECUTION_MAX_RETRY) {
                debug.error("AM Neo4j Policy Plugin: retrying ... ");
                closeDriver(driver);
                driver = null;
                return neoQuery(statement, params, ++retry);
            }
        }
        finally {
            if(session != null)
                session.close();
        }
        return null;
    }

    private void closeDriver(Driver driver) {
        try {
            driver.close();
        } catch (Exception e) {
            debug.warning("AM Neo4j Policy Plugin: Error trying to close connection:  - " + e.getMessage());
        }
    }

    private Driver getDriver() {
        Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.INFO, "hello this is Logger");
        // TODO Auto-generated method stub
        if (driver != null)
            return driver;
        debug.message("AM Neo4j Policy Plugin: Creating a new driver");
        if (dbURL.contains("bolt+routing")) {
            String[] uris = dbURL.split(",");
            List<URI> uriList = new ArrayList<>();
            for (String uri: uris) {
                uriList.add(URI.create(uri));
            }
            driver = GraphDatabase.routingDriver(uriList, AuthTokens.basic( dbUsername, dbPassword), Config.build().withLogging(Logging.console(Level.INFO)).toConfig());
        }
        else {
            driver = GraphDatabase.driver(dbURL, AuthTokens.basic( dbUsername, dbPassword) );
        }

        return driver;

    }

    @SuppressWarnings("unchecked")
    private String envMapStringify(String param, Object envMap) {
        String envMapStr = null;

        if (envMap instanceof Set) {
            Set<String> envMapSet = (Set<String>) envMap;
            if (!envMapSet.isEmpty()) {
                if (envMapSet.size() > 1) {
                    debug.warning("AM Neo4j Policy Plugin: Environment map {0} cardinality > 1. Using first from: {1}", param,
                            envMapSet);
                }
                envMapStr = envMapSet.iterator().next();
            }
        } else if (envMap instanceof String) {
            envMapStr = (String) envMap;
        }

        if (StringUtils.isBlank(envMapStr)) {
            debug.warning("AM Neo4j Policy Plugin: Environment map {0} is null or empty", param);
        }
        return envMapStr;

    }

    private String getUserId(Subject subject) throws EntitlementException {
        Principal principal = subject.getPrincipals().iterator().next();
        String subjectName = principal.getName();
        int start = subjectName.indexOf('=');
        int end = subjectName.indexOf(',');
        if (start > -1 && end > -1) { // valid userDn type input for repo users
            return subjectName.substring(start + 1, end);
        } else { // sibjectName from jwtToken or OIDC claim
            return subjectName;
        }
    }


}

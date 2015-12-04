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
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.entitlement.ConditionDecision;
import com.sun.identity.entitlement.EntitlementCondition;
import com.sun.identity.entitlement.EntitlementException;

import static com.sun.identity.entitlement.EntitlementException.PROPERTY_VALUE_NOT_DEFINED;

import com.sun.identity.entitlement.PrivilegeManager;
import com.sun.identity.shared.debug.Debug;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.apache.commons.codec.binary.Base64;
import org.forgerock.openam.core.CoreWrapper;

import static org.forgerock.openam.entitlement.conditions.environment.ConditionConstants.*;

import org.forgerock.openam.entitlement.conditions.environment.EntitlementCoreWrapper;
import org.forgerock.openam.utils.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

import sun.misc.BASE64Encoder;

/**
 * Neo4j-Universal Policy Environmental Condition Plugin for OpenAM
 * 
 * An implementation of an
 * {@link com.sun.identity.entitlement.EntitlementCondition} that will check
 * whether the principal meets condition based on a parameterized cypher 
 * query against a Neo4j graph dabatase.
 *
 * @since 12.0.0
 * @author Hadi Ahmadi
 */
public class NeoUniversalCondition implements EntitlementCondition {

    private static final String NEO_DB_URL = "neoDbURL";
    private static final String NEO_DB_USERNAME = "neoDbUsername";
    private static final String NEO_DB_PASSWORD = "neoDbPassword";
    private static final String NEO_CYPHER_QUERY = "neoCypgerQuery";
    private static final String NEO_QUERY_PARAMS = "neoQueryParams";
    // TODO Add policy advice support
    //private static final String NEO_ADVICE_MAP = "neoAdviceMap";
    private static final String NEO_ALLOW_RESULT = "neoAllowResult";
    private static final String NEO_DENY_RESULT = "neoDenyResult";

    private final Debug debug;
    private final CoreWrapper coreWrapper;
    private final EntitlementCoreWrapper entitlementCoreWrapper;

    private String dbURL = null;
    private String dbUsername = null;
    private String dbPassword = null;
    private String cypherQuery = null;
    private String paramsJson = null;
    //private String adviceMapJson = null;
    private String allowCypherResult = null;
    private String denyCypherResult = null;

    private boolean realmEmpty = false;
    private String displayType;

    @Override
    public void setDisplayType(String displayType) {
        this.displayType = displayType;
    }

    @Override
    public String getDisplayType() {
        return displayType;
    }

    public String getDbURL() {
        return dbURL;
    }

    public String getDbUsername() {
        return dbUsername;
    }

    public String getDbPassword() {
        return dbPassword;
    }

    public String getCypherQuery() {
        return cypherQuery;
    }

    public String getParamsJson() {
        return paramsJson;
    }

    /*public String getAdviceMapJson() {
     return adviceMapJson;
     }*/
    public String getAllowCypherResult() {
        return allowCypherResult;
    }

    public String getDenyCypherResult() {
        return denyCypherResult;
    }

    public void setDbURL(String dbURL) {
        this.dbURL = dbURL;
    }

    public void setDbUsername(String dbUsername) {
        this.dbUsername = dbUsername;
    }

    public void setDbPassword(String dbPassword) {
        this.dbPassword = dbPassword;
    }

    public void setCypherQuery(String cypherQuery) {
        this.cypherQuery = cypherQuery;
    }

    public void setParamsJson(String ParamsJson) {
        this.paramsJson = ParamsJson;
    }

    /* public void setAdviceMapJson(String adviceMapJson) {
     this.adviceMapJson = adviceMapJson;
     }*/
    public void setAllowCypherResult(String allowCypherResult) {
        this.allowCypherResult = allowCypherResult;
    }

    public void setDenyCypherResult(String denyCypherResult) {
        this.denyCypherResult = denyCypherResult;
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
            } /*else if (key.equalsIgnoreCase(NEO_ADVICE_MAP)) {
             setAdviceMapJson(getStringValue(map.get(key)));
             } */ else if (key.equalsIgnoreCase(NEO_ALLOW_RESULT)) {
                setAllowCypherResult(getStringValue(map.get(key)));
            } else if (key.equalsIgnoreCase(NEO_DENY_RESULT)) {
                setDenyCypherResult(getStringValue(map.get(key)));
            }
        }
    }

    private static String getInitStringValue(Set<String> set) {
        return ((set == null) || set.isEmpty()) ? "" : set.iterator().next();
    }

    private static String getStringValue(Set<String> set) {
        return ((set == null) || set.isEmpty()) ? null : set.iterator().next();
    }

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
            /* if (jo.has(NEO_ADVICE_MAP)) {
             setAdviceMapJson(jo.getString(NEO_ADVICE_MAP));
             }*/
            if (jo.has(NEO_ALLOW_RESULT)) {
                setAllowCypherResult(jo.getString(NEO_ALLOW_RESULT));
            }
            if (jo.has(NEO_DENY_RESULT)) {
                setDenyCypherResult(jo.getString(NEO_DENY_RESULT));
            }

        } catch (JSONException e) {
            debug.message("NeoUniversalCondition: Failed to set state", e);
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
            //  jo.put(NEO_ADVICE_MAP, adviceMapJson);
            jo.put(NEO_ALLOW_RESULT, allowCypherResult);
            jo.put(NEO_DENY_RESULT, denyCypherResult);
        } catch (JSONException ex) {
            Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
        }
        return jo.toString();
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("deprecation")
	@Override
    public ConditionDecision evaluate(String realm, Subject subject, String resourceName, Map<String, Set<String>> env)
            throws EntitlementException {

        Map<String, Set<String>> advices = new HashMap<String, Set<String>>();

        if (!subject.getPrincipals().isEmpty()) {
            try {
                String cypherResult = null;

                JSONObject params = sanitizeParams(paramsJson, realm, subject, resourceName, env);
                JSONObject query = new JSONObject();
                query.put("statement", cypherQuery);
                query.put("parameters", params);

                JSONObject data = neoQuery(query);

                if (data != null) {
                    cypherResult = data.getJSONArray("row").getString(0);
                } else {
                    throw new ConnectionException("Error response received from the Graph DB while querying NeoClientType!");
                }

                if (cypherResult.equalsIgnoreCase(allowCypherResult)) {
                    return new ConditionDecision(true, advices);
                } else if (cypherResult.equalsIgnoreCase(denyCypherResult)) {
                    return new ConditionDecision(false, advices);
                }
            } catch (JSONException ex) {
                Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ConnectionException ex) {
                Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
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

    private JSONObject sanitizeParams(String params, String realm, Subject subject, String resourceName, Map<String, Set<String>> env) throws EntitlementException {
        JSONObject jsonParams = null;
        boolean requestHasParams = false;
        Map<String, String> reqParamMap = new LinkedHashMap<String, String>();
        
        SSOToken token = (SSOToken) subject.getPrivateCredentials().iterator().next();

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
            jsonParams = new JSONObject(params);
            @SuppressWarnings("unchecked")
			Iterator<String> paramItr = jsonParams.keys();

            while (paramItr.hasNext()) {
                String paramKey = paramItr.next();
                String paramVal = jsonParams.get(paramKey).toString();
                if (paramVal.startsWith("__")) {
                    if (paramVal.equals("__userId")) {
                        if (!subject.getPrincipals().isEmpty()) {
                            String userId = getUserId(subject);
                            jsonParams.put(paramKey, userId);
                        } else {
                            throw new EntitlementException(
                                    EntitlementException.CONDITION_EVALUATION_FAILED,
                                    "could not find userId (required) from subject");
                        }
                    } else if (paramVal.equals("__resourceName")) {
                        jsonParams.put(paramKey, resourceName);
                    } else if (paramVal.equals("__realm")) {
                        jsonParams.put(paramKey, realm);
                    } else if (paramVal.startsWith("__env__")) {
                        String envParam = paramVal.substring(7);
                        String envParamVal = envMapStringify(envParam, env.get(envParam));
                        jsonParams.put(paramKey, envParamVal);
                    } else if (paramVal.startsWith("__token__")) {
                        String tokenProp = paramVal.substring(7);
                        String tokenPropVal = token.getProperty(tokenProp);
                        jsonParams.put(paramKey, tokenPropVal);
                    } else if (paramVal.startsWith("__token.")) {
                    	String tokenMethod = paramVal.substring(6);
                    	java.lang.reflect.Method method = token.getClass().getMethod(tokenMethod);
                    	String methodRet = method.invoke(token).toString();
                        jsonParams.put(paramKey, methodRet);
                    } else if (paramVal.startsWith("__req__") && requestHasParams) {
                        String reqParam = paramVal.substring(7);
                        if (reqParamMap.containsKey(reqParam)) {
                            String reqParamVal = reqParamMap.get(reqParam);
                            jsonParams.put(paramKey, reqParamVal);
                        }
                    }
                }
            }

        } catch (JSONException ex) {
            Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SSOException ex) {
        	Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchMethodException ex) {
			Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		} catch (SecurityException ex) {
			Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalAccessException ex) {
			Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		} catch (IllegalArgumentException ex) {
			Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		} catch (InvocationTargetException ex) {
			Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
		}

        return jsonParams;
    }

    private JSONObject neoQuery(JSONObject stateQuery) {
        JSONObject jsonResult = null;
        try {
            JSONObject jsonReq = new JSONObject();
            List<JSONObject> statementArray = new ArrayList<JSONObject>();
            statementArray.add(stateQuery);

            jsonReq.put("statements", statementArray);

            String creds = dbUsername + ":" + dbPassword;
            String authzHeader = "Basic " + Base64.encodeBase64String(creds.getBytes());

            Client client = Client.create();
            WebResource resource = client.resource(dbURL);
            ClientResponse response = resource.type("application/json").header("Authorization", authzHeader).post(ClientResponse.class, jsonReq.toString());

            if (response.getStatus() == 200) {
                JSONObject jsonResp = new JSONObject(response.getEntity(String.class));

                if (jsonResp.getJSONArray("errors").length() == 0) {
                    jsonResult = jsonResp.getJSONArray("results")
                            .getJSONObject(0).getJSONArray("data").getJSONObject(0);
                }
            }

        } catch (JSONException ex) {
            Logger.getLogger(NeoUniversalCondition.class.getName()).log(Level.SEVERE, null, ex);
        }
        return jsonResult;
    }

    public String getRequestIp(Map<String, Set<String>> env) {
        String ip = null;
        final Object requestIp = env.get(REQUEST_IP);

        if (requestIp instanceof Set) {
            @SuppressWarnings("unchecked")
			Set<String> requestIpSet = (Set<String>) requestIp;
            if (!requestIpSet.isEmpty()) {
                if (requestIpSet.size() > 1) {
                    debug.warning("Environment map {0} cardinality > 1. Using first from: {1}",
                            REQUEST_IP, requestIpSet);
                }
                ip = requestIpSet.iterator().next();
            }
        } else if (requestIp instanceof String) {
            ip = (String) requestIp;
        }

        if (StringUtils.isBlank(ip)) {
            debug.warning("Environment map {0} is null or empty", REQUEST_IP);
        }
        return ip;
    }

    @SuppressWarnings("unchecked")
	private String envMapStringify(String param, Object envMap) {
        String envMapStr = null;

        if (envMap instanceof Set) {
            Set<String> envMapSet = (Set<String>) envMap;
            if (!envMapSet.isEmpty()) {
                if (envMapSet.size() > 1) {
                    debug.warning("Environment map {0} cardinality > 1. Using first from: {1}", param,
                            envMapSet);
                }
                envMapStr = envMapSet.iterator().next();
            }
        } else if (envMap instanceof String) {
            envMapStr = (String) envMap;
        }

        if (StringUtils.isBlank(envMapStr)) {
            debug.warning("Environment map {0} is null or empty", param);
        }
        return envMapStr;

    }

    private String getUserId(Subject subject) throws EntitlementException {
        Principal principal = subject.getPrincipals().iterator().next();
        String userDn = principal.getName();
        int start = userDn.indexOf('=');
        int end = userDn.indexOf(',');
        if (end <= start) {
            throw new EntitlementException(
                    EntitlementException.CONDITION_EVALUATION_FAILED,
                    "Name is not a valid DN: " + userDn);
        }
        String userId = userDn.substring(start + 1, end);
        return userId;
    }

}

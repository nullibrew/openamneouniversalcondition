# OpenAM Universal Neo Policy Evaluation Plugin

This project introduces an OpenAM environment condition plugin, named Neo Universal Condition plugin, to be integrated and used by the OpenAM policy engine. The plugin interface allows IAM developers to write their own policy conditions via Neo4j Cypher query language. This provides OpenAM developers to practice graph-based access control and its effectiveness in many different authorization scenarios.


## Building the Plugin

Before building the plugin,
update the POM property `<openam.version>` to match your OpenAM version.

The line to update is:

    <openam.version>13.0.0-SNAPSHOT</openam.version>

Build the plugin using Apache Maven.

    mvn install

**Note**

The project build depends on is OpenAM 13.0.0-SNAPSHOT, but has been tested to work with OpenAM 12.0.0 and OpenAM 12.0.2 as well.

The plugin has been tested to work with JDK 7 and 8 and on Apache Tomcat 7 as OpenAM Container.


## Installing the Plugin

After successfully building the plugin,
copy the library to the `WEB-INF/lib/` directory where you deployed OpenAM.
For OpenAM deployed on Apache Tomcat under `/openam`:

    cp target/*.jar /path/to/tomcat/webapps/openam/WEB-INF/lib/
    cp other/*.jar /path/to/tomcat/webapps/openam/WEB-INF/lib/

Next, edit the `policyEditor/locales/en/translation.json` file
to add the strings used by the policy editor
so that the policy editor shows the custom subject and condition.

    "conditionTypes": {
      ...
       "NeoUniversal": {
              "title": "Neo Universal Condition",
              "props": {
                  "dbURL": "DB bolt Endpoint URL",
                  "dbUsername": "DB Username",
                  "dbPassword": "DB Password",
                  "cypherQuery": "Cypher Query",
                  "paramsJson": "Query Parameters (JSON)",
                  "allowCypherResult": "Cypher Result for Allow-Access",
                  "denyCypherResult": "Cypher Result for Deny-Access"
              }
          },
        ...

Restart OpenAM or the container in which it runs.

    /path/to/tomcat/bin/shutdown.sh
    ...
    /path/to/tomcat/bin/startup.sh

Your custom policy plugin can now be used for new policy applications.



## Adding Custom Policy Implementations to Existing Policy Applications

In order to use the Neo Universal Condition policy in existing applications,
you must update the applications.
Note that you cannot update an application that already has policies configured.
When there are already policies configured for an application,
you must instead first delete the policies, and then update the application.

The following example updates the `iPlanetAMWebAgentService` application
in the top level realm of a fresh installation.

    curl \
     --request POST \
     --header "X-OpenAM-Username: amadmin" \
     --header "X-OpenAM-Password: password" \
     --header "Content-Type: application/json" \
     --data "{}" \
     http://openam.example.com:8080/openam/json/authenticate

    {"tokenId":"AQIC5wM2...","successUrl":"/openam/console"}

    curl \
     --request PUT \
     --header "iPlanetDirectoryPro: AQIC5wM2..." \
     --header "Content-Type: application/json" \
     --data '{
        "name": "iPlanetAMWebAgentService",
        "resourceTypeUuids": [
        "76656a38-5f8e-401b-83aa-4ccb74ce88d2"
        ],
        "realm": "/",
        "resources": [
            "*://*:*/*?*",
            "*://*:*/*"
        ],
        "actions": {
            "POST": true,
            "PATCH": true,
            "GET": true,
            "DELETE": true,
            "OPTIONS": true,
            "HEAD": true,
            "PUT": true
        },
        "description": "The built-in Application used by OpenAM Policy Agents.",
        "realm": "/",
        "conditions": [
            "AuthenticateToService",
            "AuthLevelLE",
            "AuthScheme",
            "IPv6",
            "SimpleTime",
            "OAuth2Scope",
            "IPv4",
            "AuthenticateToRealm",
            "OR",
            "AMIdentityMembership",
            "LDAPFilter",
            "AuthLevel",
            "SessionProperty",
            "Session",
            "NOT",
            "AND",
            "ResourceEnvIP",
            "NeoUniversal"
        ],
        "resourceComparator": null,
        "applicationType": "iPlanetAMWebAgentService",
        "subjects": [
            "JwtClaim",
            "AuthenticatedUsers",
            "Identity",
            "NOT",
            "AND",
            "NONE",
            "OR"
        ],
        "attributeNames": [],
        "saveIndex": null,
        "searchIndex": null,
        "entitlementCombiner": "DenyOverride"
    }' http://openam.example.com:8088/openam/json/applications/iPlanetAMWebAgentService

Notice that the command adds `"NeoUniversal"` to `"conditions"`.

The `"resourceTypeUuids"` can be found using

    curl \
    --header "iPlanetDirectoryPro: AQIC5wM2LY4SfczmdAmN0Oh33heyIkja8....." \
    --get --data-urlencode '_queryFilter=name co "URL"' http://openam.example.com:8088/openam/json/resourcetypes
    

## Trying the Neo Universal Condition

Install and configure Neo4j graph db and create appropriate nodes and relationships, so that allow/deny access can be mapped to a true/false return value from a Cypher-language query. Also set up an Apache web server, say accessible via "http://www.example.com:80", which and index.html page as a resource for testing purposes.

Using OpenAM policy editor, create a policy in the "iPlanetAMWebAgentService" of the top level realm
that allows HTTP GET access to `"http://www.example.com:80/*"` and that makes use of the Neo Universal Condition.

    {
        "name": "Neo Policy",
        "active": true,
        "description": "Try Neo Universal Condition",
        "resources": [
            "http://www.example.com:80/*"
        ],
        "applicationName": "iPlanetAMWebAgentService",
        "actionValues": {
            "GET": true
        },
        "condition": {
            "type": "NeoUniversal",
            "dbURL": "[DB bolt endpoint URL]",
            "dbUsername": "[Neo4j username]",
            "dbPassword": "[Neo4j password]",
            "cypherQuery": "[Cypher-language query - assume it returns 'return' which is 'true' or 'false']",
            "paramsJson": {"[PARAM_NAME]": "[PARAM_VALUE]", ...},
            "allowCypherResult": "true",
            "denyCypherResult": "false"
        }
    }

To test the Neo Universal Condition plugin, try accessing the resource at "http://www.example.com:80/index.html", authenticate and see if access decision matches the condition enforced by the Neo Universal Plugin. The bolt endpoint for neo4j on localhost is "bolt://localhost".



* * * * *

Everything in this repository is licensed under the ForgeRock CDDL license:
<http://forgerock.org/license/CDDLv1.0.html>

Copyright 2013-2014 ForgeRock AS
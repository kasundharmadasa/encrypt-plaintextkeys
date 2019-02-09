/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.token.encryptor.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.token.encryptor.DbUtils;
import org.wso2.carbon.token.encryptor.IdnAccessToken;
import org.wso2.carbon.token.encryptor.IdnAuthorizationCode;
import org.wso2.carbon.token.encryptor.IdnOauthApplication;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * @scr.component name="org.wso2.carbon.token.encryptor" immediate="true"
 * @scr.reference name="config.context.service" interface="org.wso2.carbon.utils.ConfigurationContextService"
 * cardinality="1..1" policy="dynamic"  bind="setConfigurationContextService" unbind="unsetConfigurationContextService"
 */

public class ActivatorComponent {

    private static final Log log = LogFactory.getLog(ActivatorComponent.class);

    /**
     * Method to activate bundle.
     *
     * @param context OSGi component context.
     */
    protected void activate(ComponentContext context) throws SQLException {

        if (System.getProperty("encrypt") == null) {
            return;
        }
        log.info("Token Encryptor activates");
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        connection.setAutoCommit(false);
        DbUtils dbUtils = new DbUtils(connection);
        List<IdnOauthApplication> idnOauthApplicationList = dbUtils.getOauthAppsList();
        List<IdnAccessToken> idnAccessTokenList = dbUtils.getAccessTokenList();
        List<IdnAuthorizationCode> idnAuthorizationCodeList = dbUtils.getAuthorizationCodeList();

        log.info("--------------------------- Client secrets encryption started. ---------------------------");
        dbUtils.saveClientSecret(idnOauthApplicationList);
        log.info("--------------------------- Client secrets encryption Completed. ---------------------------");
        log.info("--------------------------- Token encryption started. ---------------------------");
        dbUtils.saveApplicationTokens(idnAccessTokenList);
        log.info("--------------------------- Token encryption Completed. ---------------------------");
        log.info("--------------------------- Authorization Code encryption started. ---------------------------");
        dbUtils.saveAuthorizationCodes(idnAuthorizationCodeList);
        log.info("--------------------------- Authorization Code encryption Completed. ---------------------------");
        connection.close();
    }

    protected void setConfigurationContextService(ConfigurationContextService registryService) {

        log.info("Registry Service Found by encryptor");
        // Do nothing
    }

    protected void unsetConfigurationContextService(ConfigurationContextService registryService) {
        // Do nothing
    }
}

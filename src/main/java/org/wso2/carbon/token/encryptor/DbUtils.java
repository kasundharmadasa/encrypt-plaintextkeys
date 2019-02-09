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

package org.wso2.carbon.token.encryptor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to manipulate db related operations.
 */
public class DbUtils {

    private static final Log log = LogFactory.getLog(DbUtils.class);

    /**
     * Select data from database, Related to consumer secrete.
     */
    private final String selectQueryOauthApps = "SELECT CONSUMER_KEY, CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS";

    /**
     * Update query to save encrypted consumer secrete.
     */
    private final String updateQueryOauthApps = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CONSUMER_SECRET = ? WHERE CONSUMER_KEY = ?";

    /**
     * Select query for access token and refresh tokens.
     */
    private final String selectQueryAccessTokens = "SELECT TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN";

    /**
     * Update query to save encrypted client access and refresh token.
     */
    private final String updateQueryAccessTokens = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET ACCESS_TOKEN = ?, REFRESH_TOKEN = ? WHERE TOKEN_ID = ?";

    private final String selectQueryAuthorizationCodes = "SELECT CODE_ID, AUTHORIZATION_CODE FROM IDN_OAUTH2_AUTHORIZATION_CODE";

    private final String updateQueryAuthorizationCodes = "UPDATE IDN_OAUTH2_AUTHORIZATION_CODE SET AUTHORIZATION_CODE = ? WHERE CODE_ID = ?";

    /**
     * Database connection.
     */
    private Connection databaseConnection;

    /**
     * Constructor.
     *
     * @param databaseConnection
     */
    public DbUtils(Connection databaseConnection) {

        this.databaseConnection = databaseConnection;
    }

    /**
     * Get tokens from database.
     *
     * @return
     */
    public List<IdnAccessToken> getAccessTokenList() {

        List<IdnAccessToken> accessTokens = new ArrayList<>();

        try (Statement statement = databaseConnection.createStatement();
             ResultSet resultSet = statement.executeQuery(selectQueryAccessTokens)) {
            while (resultSet.next()) {
                IdnAccessToken temp = new IdnAccessToken();
                temp.setId(resultSet.getString("TOKEN_ID"));
                temp.setAccessToken(resultSet.getString("ACCESS_TOKEN"));
                temp.setRefreshToken(resultSet.getString("REFRESH_TOKEN"));
                accessTokens.add(temp);
            }
        } catch (SQLException e) {
            log.error("Unable to retrieve the access token list", e);
        }
        return accessTokens;
    }

    /**
     * Get authorization codes from database.
     *
     * @return
     */
    public List<IdnAuthorizationCode> getAuthorizationCodeList() {

        List<IdnAuthorizationCode> authorizationCodes = new ArrayList<>();

        try (Statement statement = databaseConnection.createStatement();
             ResultSet resultSet = statement.executeQuery(selectQueryAuthorizationCodes)) {
            while (resultSet.next()) {
                IdnAuthorizationCode temp = new IdnAuthorizationCode();
                temp.setId(resultSet.getString("CODE_ID"));
                temp.setAuthorizationCode(resultSet.getString("AUTHORIZATION_CODE"));
                authorizationCodes.add(temp);
            }
        } catch (SQLException e) {
            log.error("Unable to retrieve authorization codes", e);
        }
        return authorizationCodes;
    }

    /**
     * Get list of applications with client secret.
     *
     * @return
     */
    public List<IdnOauthApplication> getOauthAppsList() {

        List<IdnOauthApplication> apps = new ArrayList<>();

        try (Statement statement = databaseConnection.createStatement();
             ResultSet resultSet = statement.executeQuery(selectQueryOauthApps)) {
            while (resultSet.next()) {
                IdnOauthApplication temp = new IdnOauthApplication();
                temp.setId(resultSet.getString("CONSUMER_KEY"));
                temp.setClientSecret(resultSet.getString("CONSUMER_SECRET"));
                apps.add(temp);
            }
        } catch (SQLException e) {
            log.error("Unable to retrieve Oauth consumer app list", e);
        }
        return apps;
    }

    /**
     * Encrypt and save client secrets.
     *
     * @param idnOauthApplicationList
     * @throws SQLException
     */
    public void saveClientSecret(List<IdnOauthApplication> idnOauthApplicationList) throws SQLException {

        try (PreparedStatement statement = databaseConnection.prepareStatement(updateQueryOauthApps)) {
            for (IdnOauthApplication tempapp : idnOauthApplicationList) {
                String convertedToken = null;
                if (log.isDebugEnabled()) {
                    log.debug("Encrypting client secret for the client ID: " + tempapp.getId());
                }
                convertedToken = TokenProcessor.getEncryptedToken(tempapp.getClientSecret());
                databaseConnection.setAutoCommit(false);
                statement.setString(1, convertedToken);
                statement.setString(2, tempapp.getId());
                statement.addBatch();
            }
            int[] execution = statement.executeBatch();
            databaseConnection.commit();
            log.info("Client Secrets Converted : " + execution);
        } catch (Exception e) {
            log.error("Unable to update Client secrets ", e);
            databaseConnection.rollback();
        }
    }

    /**
     * Encrypt and save access and refresh tokens.
     *
     * @param idnAccessTokens
     * @throws SQLException
     */
    public void saveApplicationTokens(List<IdnAccessToken> idnAccessTokens) throws SQLException {

        try (PreparedStatement statement = databaseConnection.prepareStatement(updateQueryAccessTokens)) {
            for (IdnAccessToken temptokens : idnAccessTokens) {
                String convertedaccessToken;
                String convertedrefreshToken;
                if (log.isDebugEnabled()) {
                    log.debug("Encrypting access token and refresh token for the token ID: " + temptokens.getId());
                }
                convertedaccessToken = TokenProcessor.getEncryptedToken(temptokens.getAccessToken());
                convertedrefreshToken = TokenProcessor.getEncryptedToken(temptokens.getRefreshToken());

                databaseConnection.setAutoCommit(false);
                statement.setString(1, convertedaccessToken);
                statement.setString(2, convertedrefreshToken);
                statement.setString(3, temptokens.getId());
                statement.addBatch();
            }
            int[] execution = statement.executeBatch();
            databaseConnection.commit();
            log.info("Tokens Converted :" + execution);
        } catch (Exception e) {
            log.error("Unable to update Oauth2 tokens.", e);
            databaseConnection.rollback();
        }
    }

    /**
     * Encrypt and save authorization codes.
     *
     * @param authorizationCodes
     * @throws SQLException
     */
    public void saveAuthorizationCodes(List<IdnAuthorizationCode> authorizationCodes) throws SQLException {

        try (PreparedStatement statement = databaseConnection.prepareStatement(updateQueryAuthorizationCodes)) {
            for (IdnAuthorizationCode authorizationCode : authorizationCodes) {
                String encryptedAuthorizationCodes;
                if (log.isDebugEnabled()) {
                    log.debug("Encrypting authorization code for the code ID: " + authorizationCode.getId());
                }
                encryptedAuthorizationCodes =
                        TokenProcessor.getEncryptedToken(authorizationCode.getAuthorizationCode());

                databaseConnection.setAutoCommit(false);
                statement.setString(1, encryptedAuthorizationCodes);
                statement.setString(2, authorizationCode.getId());
                statement.addBatch();
            }
            int[] execution = statement.executeBatch();
            databaseConnection.commit();
            log.info("Authorization codes converted :" + execution);
        } catch (Exception e) {
            log.error("Unable to update Oauth2 authorization codes.", e);
            databaseConnection.rollback();
        }
    }

}

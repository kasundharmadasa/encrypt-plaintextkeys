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
    private final String selectQueryOauthApps = "SELECT ID, CONSUMER_SECRET FROM IDN_OAUTH_CONSUMER_APPS";

    /**
     * Update query to save encrypted consumer secrete.
     */
    private final String updateQueryOauthApps = "UPDATE IDN_OAUTH_CONSUMER_APPS SET CONSUMER_SECRET = ? WHERE ID = ?";

    /**
     * Select query for access token and refresh tokens.
     */
    private final String selectQueryAccessTokens = "SELECT TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN";

    /**
     * Update query to save encrypted client access and refresh token.
     */
    private final String updateQueryAccessTokens = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET ACCESS_TOKEN = ?, REFRESH_TOKEN FROM = ? WHERE TOKEN_ID = ?";

    /**
     * Database connection.
     */
    private Connection databaseConnection;

    /**
     * Constructor.
     * @param databaseConnection
     */
    public DbUtils(Connection databaseConnection) {

        this.databaseConnection = databaseConnection;
    }

    public List<IdnAccessToken> getAccessTokenList()
    {
        try {
            Statement statement = databaseConnection.createStatement();
            ResultSet resultSet = statement.executeQuery(selectQueryAccessTokens);
            List<IdnAccessToken> accessTokens = new ArrayList<>();
            while(resultSet.next())
            {
                IdnAccessToken temp = new IdnAccessToken();
                temp.setId(resultSet.getString("TOKEN_ID"));
                temp.setAccessToken(resultSet.getString("ACCESS_TOKEN"));
                temp.setRefreshToken(resultSet.getString("REFRESH_TOKEN"));
                accessTokens.add(temp);
            }
            return accessTokens;
        } catch (SQLException e) {
            log.error("Unable to execute query");
            e.printStackTrace();
            return null;
        }
    }

    public List<IdnOauthApplication> getOauthAppsList()
    {
        try {
            Statement statement = databaseConnection.createStatement();
            ResultSet resultSet = statement.executeQuery(selectQueryOauthApps);
            List<IdnOauthApplication> apps = new ArrayList<>();
            while(resultSet.next())
            {
                IdnOauthApplication temp = new IdnOauthApplication();
                temp.setId(resultSet.getString("ID"));
                temp.setClientSecreat(resultSet.getString("CONSUMER_SECRET"));
                apps.add(temp);
            }
            return apps;
        } catch (SQLException e) {
            log.error("Unable to execute query");
            e.printStackTrace();
            return null;
        }
    }

    public void saveClientSecret(List<IdnOauthApplication> idnOauthApplicationList) throws SQLException {
        try {
            PreparedStatement statement = databaseConnection.prepareStatement(updateQueryOauthApps);
            for(IdnOauthApplication tempapp : idnOauthApplicationList) {
                String convertedToken = TokenProcessor.getEncryptedToken(tempapp.getClientSecreat());
                databaseConnection.setAutoCommit(false);
                statement.setString(1,convertedToken);
                statement.setString(2,tempapp.getId());
                statement.addBatch();
            }
            int [] execution = statement.executeBatch();
            databaseConnection.commit();
            log.info("Client Secrets Converted :" +execution);
        } catch (SQLException e) {
            log.error("Unable to update Client secrets ");
            databaseConnection.rollback();
            e.printStackTrace();
        }
    }

    public void saveApplicationTokens(List<IdnAccessToken> idnAccessTokens) throws SQLException {
        try {
            PreparedStatement statement = databaseConnection.prepareStatement(updateQueryAccessTokens);
            for(IdnAccessToken temptokens : idnAccessTokens) {
                String convertedaccessToken = TokenProcessor.getEncryptedToken(temptokens.getAccessToken());
                String convertedrefreshToken = TokenProcessor.getEncryptedToken(temptokens.getRefreshToken());
                databaseConnection.setAutoCommit(false);
                statement.setString(1,convertedaccessToken);
                statement.setString(2,convertedrefreshToken);
                statement.setString(2,temptokens.getId());
                statement.addBatch();
            }
            int [] execution = statement.executeBatch();
            databaseConnection.commit();
            log.info("Tokens Converted :" +execution);
        } catch (SQLException e) {
            log.error("Unable to update Tokens ");
            databaseConnection.rollback();
            e.printStackTrace();
        }
    }

}

# Plain text migrator for WSO2 products

This tool could use to encrypt plaintext keys in wso2 products. Purpose of developing this tool is to overcome the difficulties when using encryption (By setting up EncryptionDecryptionPersistenceProcessor) and already data is stored in plain text.

# Running the tool

  - Build the tool using with maven
  ```sh
$ mvn clean install
```
  - copy the .jar file (located in target folder) to <IS_HOME>/repository/components/dropins folder.
  - start the server using following command.
  
  ```sh
$ ./wso2server.sh -Dencrypt 
```
### Please note that the following tables are get affected.

- IDN_OAUTH2_ACCESS_TOKEN
- IDN_OAUTH_CONSUMER_APPS

***Please backup your relevant databases before running this tool in case of emergency.*

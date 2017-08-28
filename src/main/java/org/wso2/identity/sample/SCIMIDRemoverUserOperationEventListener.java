/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.identity.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

/**
 * Avoid manually updating auto-generated attributes in the Active Directory
 */
public class SCIMIDRemoverUserOperationEventListener extends AbstractIdentityUserOperationEventListener {


    public static final String ID_URI = "urn:scim:schemas:core:1.0:id";
    public static final String META_CREATED_URI = "urn:scim:schemas:core:1.0:meta.created";
    public static final String META_LAST_MODIFIED_URI = "urn:scim:schemas:core:1.0:meta.lastModified";
    public static final String META_LOCATION_URI = "urn:scim:schemas:core:1.0:meta.location";
    private static Log log = LogFactory.getLog(SCIMIDRemoverUserOperationEventListener.class);

    @Override
    public boolean doPreAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                String profile, UserStoreManager userStoreManager) throws UserStoreException {

        log.info("doPreAddUser()");

        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.ID_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.ID_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);

        return true;
    }


    @Override
    public boolean doPostAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                 String profile, UserStoreManager userStoreManager) throws UserStoreException {

        log.info("doPostAddUser()");

        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        String[] claimURIs = new String[]{SCIMIDRemoverUserOperationEventListener.ID_URI,
                SCIMIDRemoverUserOperationEventListener.META_CREATED_URI, SCIMIDRemoverUserOperationEventListener
                .META_LAST_MODIFIED_URI};

        log.info("Retrieving claim values for : " + Arrays.deepToString(claimURIs));

        Map<String, String> claimURLValueMappings = userStoreManager.getUserClaimValues(userName, claimURIs, profile);

        for (Map.Entry<String, String> entry : claimURLValueMappings.entrySet()) {
            log.info("Setting claim : " + entry.getKey() + " value: " + entry.getValue());
            claims.put(entry.getKey(), entry.getValue());
        }

        return true;
    }


    @Override
    public boolean doPreSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                           UserStoreManager userStoreManager) throws UserStoreException {

        log.info("doPreSetUserClaimValues()");

        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.ID_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.ID_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);
        log.info("removing scim: " + SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);
        claims.remove(SCIMIDRemoverUserOperationEventListener.META_LOCATION_URI);

        return true;
    }

    @Override
    public boolean doPostGetUserClaimValues(String userName, String[] claims, String profileName, Map<String, String>
            claimMap, UserStoreManager userStoreManager) throws UserStoreException {

        log.info("doPostGetUserClaimValues()");

        try {
            if (!isEnable() || !userStoreManager.isSCIMEnabled()) {
                return true;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error while reading isScimEnabled from userstore manager", e);
        }

        if (!(userStoreManager instanceof ActiveDirectoryUserStoreManager)) {
            return true;
        }

        if (claimMap.containsKey(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI)) {
            String createdTime = claimMap.get(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI);

            try {
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> Before: " + SCIMIDRemoverUserOperationEventListener
                        .META_CREATED_URI + " : " + createdTime);
                String formattedDate = convertDateTimeFormat(createdTime);
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> After: " + SCIMIDRemoverUserOperationEventListener
                        .META_CREATED_URI + " : " + formattedDate);
                claimMap.put(SCIMIDRemoverUserOperationEventListener.META_CREATED_URI, formattedDate);
            } catch (ParseException e) {
                log.error(">>>>>>>>>>>>>>>>>>>>>>>>>>> Error while converting claim: " +
                        SCIMIDRemoverUserOperationEventListener.META_CREATED_URI, e);
            }
        }

        if (claimMap.containsKey(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI)) {
            String modifiedTime = claimMap.get(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI);

            try {
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> Before: " + SCIMIDRemoverUserOperationEventListener
                        .META_LAST_MODIFIED_URI + " : " + modifiedTime);
                String formattedDate = convertDateTimeFormat(modifiedTime);
                log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>> After: " + SCIMIDRemoverUserOperationEventListener
                        .META_LAST_MODIFIED_URI + " : " + formattedDate);
                claimMap.put(SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI, formattedDate);
            } catch (ParseException e) {
                log.error(">>>>>>>>>>>>>>>>>>>>>>>>>>> Error while converting claim: " +
                        SCIMIDRemoverUserOperationEventListener.META_LAST_MODIFIED_URI, e);
            }
        }

        return true;
    }

    private String convertDateTimeFormat(String createdTime) throws ParseException {
        DateFormat originalFormat = new SimpleDateFormat("yyyyMMddHHmmss.SX");
        DateFormat targetFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        Date date = originalFormat.parse(createdTime);
        return targetFormat.format(date);
    }


    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 91;
    }

}

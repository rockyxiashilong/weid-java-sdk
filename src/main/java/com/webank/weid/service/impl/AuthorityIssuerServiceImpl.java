/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
 *
 *       This file is part of weidentity-java-sdk.
 *
 *       weidentity-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weidentity-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weidentity-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.service.impl;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.web3j.abi.datatypes.Address;
import org.fisco.bcos.web3j.protocol.core.methods.response.TransactionReceipt;
import org.fisco.bcos.web3j.tuples.generated.Tuple2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.webank.weid.config.ContractConfig;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.constant.WeIdConstant;
import com.webank.weid.contract.AuthorityIssuerController;
import com.webank.weid.contract.AuthorityIssuerController.AuthorityIssuerRetLogEventResponse;
import com.webank.weid.contract.SpecificIssuerController;
import com.webank.weid.contract.SpecificIssuerController.SpecificIssuerRetLogEventResponse;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.request.RegisterAuthorityIssuerArgs;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.protocol.response.TransactionInfo;
import com.webank.weid.rpc.AuthorityIssuerService;
import com.webank.weid.rpc.WeIdService;
import com.webank.weid.service.BaseService;
import com.webank.weid.util.DataToolUtils;
import com.webank.weid.util.TransactionUtils;
import com.webank.weid.util.WeIdUtils;

/**
 * Service implementations for operations on Authority Issuer.
 *
 * @author chaoxinhu 2018.10
 */
@Component
public class AuthorityIssuerServiceImpl extends BaseService implements AuthorityIssuerService {

    private static final Logger logger = LoggerFactory.getLogger(AuthorityIssuerServiceImpl.class);

    private static AuthorityIssuerController authorityIssuerController;
    private static String authorityIssuerControllerAddress;
    private static SpecificIssuerController specificIssuerController;
    private static String specificIssuerControllerAddress;

    private WeIdService weIdService = new WeIdServiceImpl();

    /**
     * Instantiates a new authority issuer service impl.
     */
    public AuthorityIssuerServiceImpl() {
        init();
    }

    private static void init() {
        ContractConfig config = context.getBean(ContractConfig.class);
        authorityIssuerController =
            (AuthorityIssuerController)
                getContractService(config.getIssuerAddress(), AuthorityIssuerController.class);
        authorityIssuerControllerAddress = config.getIssuerAddress();
        specificIssuerController = (SpecificIssuerController) getContractService(
            config.getSpecificIssuerAddress(), SpecificIssuerController.class);
        specificIssuerControllerAddress = config.getSpecificIssuerAddress();
    }

    /**
     * Use the given private key to send the transaction to call the contract.
     *
     * @param privateKey the private key
     */
    private static void reloadAuthorityIssuerContract(String privateKey) {
        authorityIssuerController = (AuthorityIssuerController) reloadContract(
            authorityIssuerControllerAddress,
            privateKey,
            AuthorityIssuerController.class
        );
    }

    private static void reloadSpecificIssuerContract(String privateKey) {
        specificIssuerController = (SpecificIssuerController) reloadContract(
            specificIssuerControllerAddress,
            privateKey,
            SpecificIssuerController.class
        );
    }

    /**
     * Register a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> registerAuthorityIssuer(RegisterAuthorityIssuerArgs args) {

    	ErrorCode innerResponseData = checkRegisterAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }

        AuthorityIssuer authorityIssuer = args.getAuthorityIssuer();
        String weAddress = WeIdUtils.convertWeIdToAddress(authorityIssuer.getWeId());
        List<byte[]> stringAttributes = new ArrayList<byte[]>();
        stringAttributes.add(authorityIssuer.getName().getBytes());
        List<BigInteger>longAttributes = new ArrayList<>();
        Long createDate = System.currentTimeMillis();
        longAttributes.add(BigInteger.valueOf(createDate));
        try {
        	reloadAuthorityIssuerContract(args.getWeIdPrivateKey().getPrivateKey());
            TransactionReceipt receipt = authorityIssuerController.addAuthorityIssuer(
            	weAddress,
            	DataToolUtils.bytesArrayListToBytes32ArrayList(
            	    stringAttributes,
            	    WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH
            	),
            	DataToolUtils.listToListBigInteger(
            	    longAttributes,
            	    WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH
            	),
            	authorityIssuer.getAccValue().getBytes()
            ).send();
            ErrorCode errorCode = resolveRegisterAuthorityIssuerEvents(receipt);
            TransactionInfo info = new TransactionInfo(receipt);
            if (errorCode.equals(ErrorCode.SUCCESS)) {
                return new ResponseData<>(Boolean.TRUE, ErrorCode.SUCCESS,info);
            } else {
                return new ResponseData<>(Boolean.FALSE, errorCode,info);
            }
        } catch (Exception e) {
            logger.error("register authority issuer failed.", e);
        }
        return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
    }
    
    private ErrorCode resolveRegisterAuthorityIssuerEvents(
        TransactionReceipt transactionReceipt) {
        List<AuthorityIssuerRetLogEventResponse> eventList =
        		authorityIssuerController.getAuthorityIssuerRetLogEvents(transactionReceipt);

        AuthorityIssuerRetLogEventResponse event = eventList.get(0);
        if (event != null) {
            ErrorCode errorCode = verifyAuthorityIssuerRelatedEvent(
                event,
                WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE
            );
            return errorCode;
        } else {
            logger.error(
                "register authority issuer failed due to transcation event decoding failure.");
            return ErrorCode.AUTHORITY_ISSUER_ERROR;
        }
    }
    
    private ErrorCode verifyAuthorityIssuerRelatedEvent(
        AuthorityIssuerRetLogEventResponse event,
        Integer opcode) {

        if (event.addr == null || event.operation == null || event.retCode == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        Integer eventOpcode = event.operation.intValue();
        if (eventOpcode.equals(opcode)) {
            Integer eventRetCode = event.retCode.intValue();
            return ErrorCode.getTypeByErrorCode(eventRetCode);
        } else {
            return ErrorCode.AUTHORITY_ISSUER_OPCODE_MISMATCH;
        }

    }

    /**
     * Remove a new Authority Issuer on Chain.
     *
     * @param args the args
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> removeAuthorityIssuer(RemoveAuthorityIssuerArgs args) {

        ErrorCode innerResponseData = checkRemoveAuthorityIssuerArgs(args);
        if (ErrorCode.SUCCESS.getCode() != innerResponseData.getCode()) {
            return new ResponseData<>(false, innerResponseData);
        }

        String weId = args.getWeId();
        try {
        	reloadAuthorityIssuerContract(args.getWeIdPrivateKey().getPrivateKey());
            TransactionReceipt receipt = authorityIssuerController
                .removeAuthorityIssuer(WeIdUtils.convertWeIdToAddress(weId)).send();
            List<AuthorityIssuerRetLogEventResponse> eventList =
            		authorityIssuerController.getAuthorityIssuerRetLogEvents(receipt);

            TransactionInfo info = new TransactionInfo(receipt);
            AuthorityIssuerRetLogEventResponse event = eventList.get(0);

            if (event != null) {
                ErrorCode errorCode = TransactionUtils.verifyAuthorityIssuerRelatedEvent(
                    event,
                    WeIdConstant.REMOVE_AUTHORITY_ISSUER_OPCODE
                );
                if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
                    return new ResponseData<>(false, errorCode,info);
                } else {
                    return new ResponseData<>(true, errorCode,info);
                }
            } else {
                logger.error("remove authority issuer failed, transcation event decoding failure.");
                return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR,info);
            }
        } catch (Exception e) {
            logger.error("remove authority issuer failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check whether the given weId is an authority issuer.
     *
     * @param weId the WeIdentity DID
     * @return the Boolean response data
     */
    @Override
    public ResponseData<Boolean> isAuthorityIssuer(String weId) {
    	ResponseData<Boolean> responseData = new ResponseData<Boolean>();

        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(false, ErrorCode.WEID_INVALID);
        }
        try {
            Boolean result = authorityIssuerController.isAuthorityIssuer(
            	WeIdUtils.convertWeIdToAddress(weId)).send();
            responseData.setResult(result);
            if (result) {
                responseData.setErrorCode(ErrorCode.SUCCESS);
            } else {
                responseData.setErrorCode(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS);
            }
        } catch (Exception e) {
            logger.error("check authority issuer id failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
        return responseData;
    }

    /**
     * Query the authority issuer information given weId.
     *
     * @param weId the WeIdentity DID
     * @return the AuthorityIssuer response data
     */
    @Override
    public ResponseData<AuthorityIssuer> queryAuthorityIssuerInfo(String weId) {
    	ResponseData<AuthorityIssuer> responseData = new ResponseData<>();
        if (!WeIdUtils.isWeIdValid(weId)) {
            return new ResponseData<>(null, ErrorCode.WEID_INVALID);
        }
        try {
            Tuple2<List<byte[]>, List<BigInteger>> rawResult =
                authorityIssuerController.getAuthorityIssuerInfoNonAccValue(
                	WeIdUtils.convertWeIdToAddress(weId)).send();
            if (rawResult == null) {
                return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
            }

            List<byte[]> bytes32Attributes = rawResult.getValue1();
            List<BigInteger> int256Attributes = rawResult.getValue2();

            AuthorityIssuer result = new AuthorityIssuer();
            result.setWeId(weId);
            String name = DataToolUtils.byte32ListToString(
            	bytes32Attributes,
            	WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH
            );
            Long createDate = Long
                .valueOf(int256Attributes.get(0).longValue());
            if (StringUtils.isEmpty(name) && createDate.equals(WeIdConstant.LONG_VALUE_ZERO)) {
                return new ResponseData<>(
                    null, ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS
                );
            }
            result.setName(name);
            result.setCreated(createDate);
            // Accumulator Value is unable to load due to Solidity 0.4.4 restrictions - left blank.
            result.setAccValue("");
            responseData.setResult(result);
        } catch (Exception e) {
            logger.error("query authority issuer failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
        return responseData;
    }

    /**
     * Get all of the authority issuer.
     *
     * @param index start position
     * @param num number of returned authority issuer in this request
     * @return Execution result
     */
    @Override
    public ResponseData<List<AuthorityIssuer>> getAllAuthorityIssuerList(Integer index,
        Integer num) {
        ErrorCode errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            List<String> addressList = 
                authorityIssuerController.getAuthorityIssuerAddressList(
            	    DataToolUtils.intToBigInteger(index), 
            	    DataToolUtils.intToBigInteger(num)
                ).send();

            List<AuthorityIssuer> authorityIssuerList = new ArrayList<>();
            for (String address : addressList) {
                String weId = WeIdUtils.convertAddressToWeId(address);
                ResponseData<AuthorityIssuer> innerResponseData
                    = this.queryAuthorityIssuerInfo(weId);
                if (innerResponseData.getResult() != null) {
                    authorityIssuerList.add(innerResponseData.getResult());
                }
            }
            return new ResponseData<>(authorityIssuerList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("query authority issuer list failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Register a new issuer type.
     *
     * @param callerAuth the caller
     * @param issuerType the specified issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> registerIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType
    ) {
        ErrorCode innerCode = isIssuerTypeValid(issuerType);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            reloadSpecificIssuerContract(callerAuth.getWeIdPrivateKey().getPrivateKey());
            TransactionReceipt receipt = specificIssuerController
                .registerIssuerType(DataToolUtils.stringToByte32Array(issuerType)).send();
            
            // pass-in empty address
            String emptyAddress = new Address(BigInteger.ZERO).toString();
            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, true, emptyAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode,info);
        } catch (Exception e) {
            logger.error("register issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }


    /**
     * Marked an issuer as the specified issuer type.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer who will be marked as a specific issuer type
     * @return Execution result
     */
    public ResponseData<Boolean> addIssuerIntoIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            reloadSpecificIssuerContract(callerAuth.getWeIdPrivateKey().getPrivateKey());
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            TransactionReceipt receipt = specificIssuerController.addIssuer(
            	DataToolUtils.stringToByte32Array(issuerType), 
        		issuerAddress
            ).send();
            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, true, issuerAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode, info);
        } catch (Exception e) {
            logger.error("add issuer into type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Removed an issuer from the specified issuer list.
     *
     * @param callerAuth the caller who have the access to modify this list
     * @param issuerType the specified issuer type
     * @param targetIssuerWeId the weId of the issuer to be removed from a specific issuer list
     * @return Execution result
     */
    public ResponseData<Boolean> removeIssuerFromIssuerType(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode innerCode = isSpecificTypeIssuerArgsValid(callerAuth, issuerType,
            targetIssuerWeId);
        if (innerCode != ErrorCode.SUCCESS) {
            return new ResponseData<>(false, innerCode);
        }
        try {
            reloadSpecificIssuerContract(callerAuth.getWeIdPrivateKey().getPrivateKey());
            String issuerAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
            TransactionReceipt receipt = specificIssuerController.removeIssuer(
            	DataToolUtils.stringToByte32Array(issuerType),
                issuerAddress).send();

            ErrorCode errorCode = resolveSpecificIssuerEvents(receipt, false, issuerAddress);
            TransactionInfo info = new TransactionInfo(receipt);
            return new ResponseData<>(errorCode.getCode() == ErrorCode.SUCCESS.getCode(),
                errorCode,info);
        } catch (Exception e) {
            logger.error("remove issuer from type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Check if the given WeId is belonging to a specific issuer type.
     *
     * @param issuerType the issuer type
     * @param targetIssuerWeId the WeId
     * @return true if yes, false otherwise
     */
    public ResponseData<Boolean> isSpecificTypeIssuer(
        String issuerType,
        String targetIssuerWeId
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(false, errorCode);
        }
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return new ResponseData<>(false, ErrorCode.WEID_DOES_NOT_EXIST);
        }
        try {
        	String weAddress = WeIdUtils.convertWeIdToAddress(targetIssuerWeId);
        	Boolean result = specificIssuerController.isSpecificTypeIssuer(
        	    DataToolUtils.stringToByte32Array(issuerType),
        	    weAddress
            ).send();

            if (!result) {
                return new ResponseData<>(result,
                    ErrorCode.SPECIFIC_ISSUER_CONTRACT_ERROR_ALREADY_NOT_EXIST);
            }
            return new ResponseData<>(result, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("check issuer type failed.", e);
            return new ResponseData<>(false, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    /**
     * Get all specific typed issuer in a list.
     *
     * @param issuerType the issuer type
     * @param index the start position index
     * @param num the number of issuers
     * @return the list
     */
    public ResponseData<List<String>> getAllSpecificTypeIssuerList(
        String issuerType,
        Integer index,
        Integer num
    ) {
        ErrorCode errorCode = isIssuerTypeValid(issuerType);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        errorCode = isStartEndPosValid(index, num);
        if (errorCode.getCode() != ErrorCode.SUCCESS.getCode()) {
            return new ResponseData<>(null, errorCode);
        }
        try {
            List<String> addresses = specificIssuerController.getSpecificTypeIssuerList(
                DataToolUtils.stringToByte32Array(issuerType),
                DataToolUtils.intToBigInteger(index), 
                DataToolUtils.intToBigInteger(num)
            ).send();
            
            List<String> addressList = new ArrayList<>();
            for (String addr : addresses) {
                if (!WeIdUtils.isEmptyStringAddress(addr)) {
                    addressList.add(addr);
                }
            }
            
            return new ResponseData<>(addressList, ErrorCode.SUCCESS);
        } catch (Exception e) {
            logger.error("get all specific issuers failed.", e);
            return new ResponseData<>(null, ErrorCode.AUTHORITY_ISSUER_ERROR);
        }
    }

    private ErrorCode isStartEndPosValid(Integer index, Integer num) {
        if (index == null || index < 0 || num == null || num <= 0
            || num > WeIdConstant.MAX_AUTHORITY_ISSUER_LIST_SIZE) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isSpecificTypeIssuerArgsValid(
        WeIdAuthentication callerAuth,
        String issuerType,
        String targetIssuerWeId
    ) {
        if (!weIdService.isWeIdExist(targetIssuerWeId).getResult()) {
            return ErrorCode.WEID_DOES_NOT_EXIST;
        }
        ErrorCode errorCode = isCallerAuthValid(callerAuth);
        if (errorCode.getCode() == ErrorCode.SUCCESS.getCode()) {
            return isIssuerTypeValid(issuerType);
        }
        return errorCode;
    }

    private ErrorCode resolveSpecificIssuerEvents(
        TransactionReceipt transactionReceipt,
        boolean isRegister,
        String address) {
        List<SpecificIssuerRetLogEventResponse> eventList =
            specificIssuerController.getSpecificIssuerRetLogEvents(transactionReceipt);

        SpecificIssuerRetLogEventResponse event = eventList.get(0);
        if (event != null) {
            if (isRegister) {
                // this might be the register type, or the register specific issuer case
                if (event.operation.intValue()
                    != WeIdConstant.ADD_AUTHORITY_ISSUER_OPCODE
                    || !StringUtils.equalsIgnoreCase(event.addr.toString(), address)) {
                    return ErrorCode.TRANSACTION_EXECUTE_ERROR;
                }
            } else {
                // this is the remove specific issuer case
                if (event.operation.intValue()
                    != WeIdConstant.REMOVE_AUTHORITY_ISSUER_OPCODE
                    || !StringUtils.equalsIgnoreCase(event.addr.toString(), address)) {
                    return ErrorCode.TRANSACTION_EXECUTE_ERROR;
                }
            }
            Integer eventRetCode = event.retCode.intValue();
            return ErrorCode.getTypeByErrorCode(eventRetCode);
        } else {
            logger.error(
                "specific issuer type resolution failed due to event decoding failure.");
            return ErrorCode.UNKNOW_ERROR;
        }
    }

    private ErrorCode isIssuerTypeValid(String issuerType) {
        if (StringUtils.isEmpty(issuerType)) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (issuerType.length() > WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH) {
            return ErrorCode.SPECIFIC_ISSUER_TYPE_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode isCallerAuthValid(WeIdAuthentication callerAuth) {
        if (callerAuth == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (callerAuth.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(callerAuth.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        if (!WeIdUtils.isWeIdValid(callerAuth.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRegisterAuthorityIssuerArgs(
        RegisterAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        ErrorCode errorCode = checkAuthorityIssuerArgsValidity(
            args.getAuthorityIssuer()
        );

        if (ErrorCode.SUCCESS.getCode() != errorCode.getCode()) {
            logger.error("register authority issuer format error!");
            return errorCode;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        // Need an extra check for the existence of WeIdentity DID on chain, in Register Case.
        ResponseData<Boolean> innerResponseData = weIdService
            .isWeIdExist(args.getAuthorityIssuer().getWeId());
        if (!innerResponseData.getResult()) {
            return ErrorCode.WEID_INVALID;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkRemoveAuthorityIssuerArgs(RemoveAuthorityIssuerArgs args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        if (args.getWeIdPrivateKey() == null
            || StringUtils.isEmpty(args.getWeIdPrivateKey().getPrivateKey())) {
            return ErrorCode.AUTHORITY_ISSUER_PRIVATE_KEY_ILLEGAL;
        }
        return ErrorCode.SUCCESS;
    }

    private ErrorCode checkAuthorityIssuerArgsValidity(AuthorityIssuer args) {

        if (args == null) {
            return ErrorCode.ILLEGAL_INPUT;
        }
        if (!WeIdUtils.isWeIdValid(args.getWeId())) {
            return ErrorCode.WEID_INVALID;
        }
        String name = args.getName();
        if (!isValidAuthorityIssuerName(name)) {
            return ErrorCode.AUTHORITY_ISSUER_NAME_ILLEGAL;
        }
        String accValue = args.getAccValue();
        try {
            BigInteger accValueBigInteger = new BigInteger(accValue);
            logger.info(args.getWeId() + " accValue is: " + accValueBigInteger.longValue());
        } catch (Exception e) {
            return ErrorCode.AUTHORITY_ISSUER_ACCVALUE_ILLEAGAL;
        }

        return ErrorCode.SUCCESS;
    }

    private boolean isValidAuthorityIssuerName(String name) {
        return !StringUtils.isEmpty(name)
            && name.length() < WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH
            && !StringUtils.isWhitespace(name)
            && StringUtils.isAsciiPrintable(name);
    }

//    private String[] loadNameToStringAttributes(String name) {
//        String[] nameArray = new String[WeIdConstant.AUTHORITY_ISSUER_ARRAY_LEGNTH];
//        nameArray[0] = name;
//        return nameArray;
//    }

//    private String extractNameFromBytes32Attributes(List<Bytes32> bytes32Array) {
//        StringBuffer name = new StringBuffer();
//        int maxLength = WeIdConstant.MAX_AUTHORITY_ISSUER_NAME_LENGTH / 32;
//        for (int i = 0; i < maxLength; i++) {
//            name.append(DataToolUtils.bytes32ToString(bytes32Array.get(i)));
//        }
//        return name.toString();
//    }
}

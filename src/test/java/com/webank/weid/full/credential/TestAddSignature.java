package com.webank.weid.full.credential;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.fisco.bcos.web3j.crypto.ECKeyPair;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.webank.weid.full.TestBaseUtil.createEcKeyPair;
import static com.webank.weid.util.CredentialUtils.copyCredential;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestAddSignature extends TestBaseServcie {

    private static final Logger logger = LoggerFactory.getLogger(
        TestAddSignature.class);
    private static  volatile CreateWeIdDataResult weid = null;
    private static volatile Credential credential = null;
    private static volatile Credential credentialNew = null;
    private  static volatile WeIdPrivateKey privateKey = null;

    @Override
    public synchronized void testInit() {
        super.testInit();
        if (privateKey == null) {
            weid = createWeIdWithSetAttr();
            privateKey = weid.getUserWeIdPrivateKey();
        }
        if (credential == null) {
            credential = super.createCredential(createCredentialArgs)
                .getCredential();
        }
        if (credentialNew == null) {
            credentialNew = super.createCredential(createCredentialArgsNew)
                .getCredential();
        }
    }

    /**
     * case1:signature one credential success,then signed again and again.
     */
    @Test
    public void testAddSignature_credentialTripleSigned() {
        List<Credential> credentialList = new ArrayList<>();
        credentialList.add(credential);
        Credential doubleSigned = credentialService.addSignature(credentialList,
            privateKey).getResult();
        LogUtil.info(logger, "doubleSigned Credential", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialService
            .verify(doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credentialList = new ArrayList<>();
        credentialList.add(doubleSigned);
        Credential tripleSigned = credentialService.addSignature(credentialList, privateKey)
            .getResult();
        verifyResp = credentialService.verify(tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case2:signature CredentialPojoList contain credentialPojo and signed credentialPojo
     * ,then signed again.
     */
    @Test
    public void testAddSignature_listContainSignAndOriginCredential() {
        List<Credential> credentialList = new ArrayList<>();
        credentialList.add(credentialNew);
        credentialList.add(credential);
        Credential doubleSigned = credentialService.addSignature(credentialList, privateKey)
            .getResult();
        LogUtil.info(logger, "sign credential", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialService
            .verify(doubleSigned);
        Assert.assertTrue(verifyResp.getResult());

        credentialList.add(doubleSigned);
        Credential tripleSigned = credentialService.addSignature(credentialList, privateKey)
            .getResult();
        ResponseData<Boolean> tripleVerify = credentialService.verify(tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(tripleVerify.getResult());
    }

    /**
     * case4:signature same credential.
     */
    @Test
    public void testAddSignature_credentialAreSame() {
        List<Credential> credentialList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            Credential copyCredential = copyCredential(credential);
            credentialList.add(copyCredential);
        }
        Credential doubleSigned = credentialService.addSignature(credentialList, privateKey)
            .getResult();
        LogUtil.info(logger, "", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIAL_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialService.verify(doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case5:credentiallist is null.
     */
    @Test
    public void testAddSignature_listNull() {
        ResponseData<Credential> response = credentialService.addSignature(
            null, privateKey);
        LogUtil.info(logger, "CredentialList is null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case6:credentialList is blank
     */
    @Test
    public void testAddSignature_listBlank() {
        ResponseData<Credential> response = credentialService.addSignature(
            new ArrayList<>(), privateKey);
        LogUtil.info(logger, "CredentialList is null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case7:WeIdAuthentication is null.
     */
    @Test
    public void testAddSignature_weIdAuthenticationNull() {
        List<Credential> credentialList = new ArrayList<>();
        credentialList.add(credentialNew);
        credentialList.add(credential);
        ResponseData<Credential> response = credentialService.addSignature(credentialList,
            null);
        LogUtil.info(logger, "signed privatekey null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case11:WeIdAuthentication private key create by key pair.
     */
    @Test
    public void testAddSignature_weIdAuthenticationOtherPrivateKey() {
        List<Credential> credentialList = new ArrayList<>();
        credentialList.add(credentialNew);
        credentialList.add(credential);
        PasswordKey passwordKey = createEcKeyPair();
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(passwordKey.getPrivateKey());
        ResponseData<Credential> response = credentialService.addSignature(credentialList,
            weIdPrivateKey);
        LogUtil.info(logger, "weIdAuthentication invalid key", response);
        Assert.assertEquals(ErrorCode.WEID_DOES_NOT_EXIST.getCode(),
            response.getErrorCode().intValue());
    }

}


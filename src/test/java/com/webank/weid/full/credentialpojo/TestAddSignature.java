package com.webank.weid.full.credentialpojo;

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

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.CredentialConstant;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestAddSignature extends TestBaseServcie {

    private static final Logger logger = LoggerFactory.getLogger(
        TestAddSignature.class);
    private static  volatile CreateWeIdDataResult weid = null;
    private static volatile CredentialPojo credentialPojo = null;
    private static volatile CredentialPojo credentialPojoNew = null;
    private static volatile CredentialPojo selectiveCredentialPojo = null;

    @Override
    public synchronized void testInit() {
        super.testInit();
        if (credentialPojo == null) {
            credentialPojo = super.createCredentialPojo(createCredentialPojoArgs);
        }
        if (credentialPojoNew == null) {
            credentialPojoNew = super.createCredentialPojo(createCredentialPojoArgsNew);
        }
        if (selectiveCredentialPojo == null) {
            selectiveCredentialPojo = this.createSelectiveCredentialPojo(credentialPojo);
        }
        if (weid == null) {
            weid = createWeIdWithSetAttr();
        }
    }

    /**
     * case1:signature one credentialPojo success,then signed again and again.
     */
    @Test
    public void testAddSignature_credentialPojoTripleSigned() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(selectiveCredentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "doubleSigned selectiveCredentialPojo", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case1:signature one credentialPojo success,then signed many times.
     */
    @Test
    public void testAddSignature_signedManyTimes() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "doubleSigned selectiveCredentialPojo", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());

        //signed many times
        for (int i = 0; i < 3; i++) {
            CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList,
                callerAuth).getResult();
            verifyResp = credentialPojoService.verify(tripleSigned.getIssuer(), tripleSigned);
            LogUtil.info(logger, "verify signed response", verifyResp);
            LogUtil.info(logger, "signed credentialPojo", tripleSigned);
            Assert.assertTrue(verifyResp.getResult());
            credPojoList.add(tripleSigned);
        }
    }

    /**
     * case2:signature selectiveCredentialPojo and CredentialPojo success,then signed again.
     */
    @Test
    public void testAddSignature_ListContainTwoCredentialPojo() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(selectiveCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "selectiveCredentialPojo&credentialPojo", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        credPojoList.add(selectiveCredentialPojo);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case3:signature selectiveCredentialPojo and CredentialPojo success,then signed again.
     */
    @Test
    public void testAddSignature_ListContainTwoDifferentCptId() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "selectiveCredentialPojo&credentialPojo", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        credPojoList.add(selectiveCredentialPojo);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case3:signature CredentialPojoList contain credentialPojo and signed credentialPojo
     * ,then signed again.
     */
    @Test
    public void testAddSignature_listContainSignAndOriginCredentialPojo() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "selectiveCredentialPojo&credentialPojo", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList.add(doubleSigned);
        credPojoList.add(selectiveCredentialPojo);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case4:signature selectiveCredentialPojo are same.
     */
    @Test
    public void testAddSignature_credentialPojoAreSame() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        for (int i = 0; i < 10; i++) {
            CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
            credPojoList.add(copyCredentialPojo);
        }
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        CredentialPojo doubleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        LogUtil.info(logger, "", doubleSigned);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertTrue(verifyResp.getResult());
        credPojoList = new ArrayList<>();
        credPojoList.add(doubleSigned);
        credPojoList.add(selectiveCredentialPojo);
        CredentialPojo tripleSigned = credentialPojoService.addSignature(credPojoList, callerAuth)
            .getResult();
        verifyResp = credentialPojoService.verify(doubleSigned.getIssuer(), tripleSigned);
        LogUtil.info(logger, "tripleSigned message", tripleSigned);
        Assert.assertTrue(verifyResp.getResult());
    }

    /**
     * case5:credentialPojoList is null.
     */
    @Test
    public void testAddSignature_listNull() {
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(
            null, callerAuth);
        LogUtil.info(logger, "CredentialPojoList is null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case6:credentialPojoList is blank
     */
    @Test
    public void testAddSignature_listBlank() {
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(
            new ArrayList<>(), callerAuth);
        LogUtil.info(logger, "CredentialPojoList is null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case7:WeIdAuthentication is null.
     */
    @Test
    public void testAddSignature_weIdAuthenticationNull() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            null);
        LogUtil.info(logger, "weIdAuthenticationNull", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case8:WeIdAuthentication private key not match weid.
     */
    @Test
    public void testAddSignature_weIdAuthenticationPrivateKeyInvaild() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        callerAuth.getWeIdPrivateKey().setPrivateKey("123");
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "weIdAuthentication invalid key", response);
        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case9:WeIdAuthentication private key null.
     */
    @Test
    public void testAddSignature_weIdAuthenticationPrivateKeyNull() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        callerAuth.getWeIdPrivateKey().setPrivateKey(null);
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "weIdAuthentication invalid key", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case10:WeIdAuthentication private key null.
     */
    @Test
    public void testAddSignature_weIdAuthenticationPrivateKeyBlank() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        callerAuth.getWeIdPrivateKey().setPrivateKey("");
        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "weIdAuthentication invalid key", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case11:WeIdAuthentication private key create by key pair.
     */
    @Test
    public void testAddSignature_weIdAuthenticationOtherPrivateKey() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojoNew);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);
        PasswordKey passwordKey = createEcKeyPair();
        callerAuth.getWeIdPrivateKey().setPrivateKey(passwordKey.getPrivateKey());

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "weIdAuthentication invalid key", response);
        Assert.assertEquals(ErrorCode.WEID_PRIVATEKEY_DOES_NOT_MATCH.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case12:credentialPojo issuer is not exist.
     */
    @Test
    public void testAddSignature_issuerNotExist() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        copyCredentialPojo.setIssuer("did:weid:101:0x39e5e6f663ef77409144014ceb063713b6ffffff");
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        Assert.assertEquals(ErrorCode.WEID_DOES_NOT_EXIST.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case12:signedCredentialPojo issuer is not exist.
     */
    @Test
    public void testAddSignature_signedIssuerNotExist() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "signed issuer not exist", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setIssuer("did:weid:101:0x39e5e6f663ef77409144014ceb063713b6ffffff");
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(weid.getWeId(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case13:modify credentialPojo.cptid should signed success but verify fail.
     */
    @Test
    public void testAddSignature_modifyCptId() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        copyCredentialPojo.setCptId(8886666);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CPT_NOT_EXISTS.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case13:set signed credentialPojo.cptId that not exist blockChain should verify fail.
     */
    @Test
    public void testAddSignature_signedCptIdNotExist() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "signed credentialPojo", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setCptId(888666);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CPT_NOT_EXISTS.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:modify signed credentialPojo.cptid=106 should  verify fail.
     */
    @Test
    public void testAddSignature_modifySignCptId() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setCptId(106);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case15:modify signed credentialPojo.claim should verify fail.
     */
    @Test
    public void testAddSignature_modifySignedClaim() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        Map<String,Object> claim = credentialPojo.getClaim();
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setClaim(claim);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case15:modify credentialPojo.claim should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialPojoClaim() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String,Object> claim =  credentialPojo.getClaim();
        claim.remove("age");
        copyCredentialPojo.setClaim(claim);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:signed credentialPojo.claim is null should verify fail.
     */
    @Test
    public void testAddSignature_SignedClaimNull() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        Assert.assertEquals(2,doubleSigned.getClaim().size());

        doubleSigned.setClaim(null);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:set credentialPojo.claim null success ，but verify should fail.
     */
    @Test
    public void testAddSignature_credentialPojoClaimNull() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        copyCredentialPojo.setClaim(null);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case16:modify signed credentialPojo.proof should verify fail.
     */
    @Test
    public void testAddSignature_modifySignProof() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        //modify signed proof
        Map<String,Object> proof = credentialPojo.getProof();
        doubleSigned.setProof(proof);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify credentialPojo.proof should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialProof() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> proof = copyCredentialPojo.getProof();
        proof.remove("creator");
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        Assert.assertEquals(2, doubleSigned.getClaim().size());

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify credentialPojo.proof key-value verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialProofValue() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> proof = copyCredentialPojo.getProof();
        proof.replace("creator",credentialPojo.getIssuer());
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        ArrayList<String> innerCredentialList =
            (ArrayList) doubleSigned.getClaim().get("credentialList");
        Assert.assertEquals(2, innerCredentialList.size());

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify credentialPojo.proof.type should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialProofTypeValue() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> salt = (Map<String, Object>) copyCredentialPojo.getProof().get("salt");
        salt.replace("type","123456");
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        ArrayList<String> innerCredentialList =
            (ArrayList) doubleSigned.getClaim().get("credentialList");
        Assert.assertEquals(2, innerCredentialList.size());

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify credentialPojo.issuanceDate should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialIssuanceDate() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        long currentTime = System.currentTimeMillis()/1000;
        System.out.println(currentTime);
        copyCredentialPojo.setIssuanceDate(currentTime);
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        ArrayList<String> innerCredentialList =
            (ArrayList) doubleSigned.getClaim().get("credentialList");
        Assert.assertEquals(2, innerCredentialList.size());

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify credentialPojo.expirationDate should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialExpirationDate() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        long currentTime = System.currentTimeMillis()/1000 + 1000000;
        System.out.println(currentTime);
        copyCredentialPojo.setExpirationDate(currentTime);
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        ArrayList<String> innerCredentialList =
            (ArrayList) doubleSigned.getClaim().get("credentialList");
        Assert.assertEquals(2, innerCredentialList.size());

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case16:modify signed credentialPojo.expirationDate should verify fail.
     */
    @Test
    public void testAddSignature_modifySignExpirationDate() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "add Signature info", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);
        ArrayList<String> innerCredentialList =
            (ArrayList) doubleSigned.getClaim().get("credentialList");
        Assert.assertEquals(1, innerCredentialList.size());
        long expireTime = System.currentTimeMillis()/1000 + 1000000;
        doubleSigned.setExpirationDate(expireTime);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:modify signed credentialPojo.cptid(credentialPojo.cptid) should  verify fail.
     */
    @Test
    public void testAddSignature_modifySignExistCptId() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setCptId(credentialPojo.getCptId());
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CLAIM_DATA_ILLEGAL.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:signedcredentialPojo disclosure fail.
     */
    @Test
    public void testAddSignature_signedCredentialPojoDisclosure() {
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "signed credentialPojo disclosure", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ClaimPolicy claimPolicy = new ClaimPolicy();
        claimPolicy.setFieldsToBeDisclosed("{\"name\":1,\"gender\":0,\"age\":1,\"id\":1}");

        ResponseData<CredentialPojo> selecres =
            credentialPojoService.createSelectiveCredential(doubleSigned, claimPolicy);
        LogUtil.info(logger, "TestCreateSelectiveCredential", selecres);
        Assert.assertEquals(ErrorCode.CPT_ID_ILLEGAL.getCode(), selecres.getErrorCode().intValue());
    }

    /**
     * case14:set signed credentialPojo content Null should  verify fail.
     */
    @Test
    public void testAddSignature_setSignContentNull() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setContext(null);
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CONTEXT_NOT_EXISTS.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:set signed credentialPojo content blank should  verify fail.
     */
    @Test
    public void testAddSignature_setSignContentBlank() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setContext("");
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_CONTEXT_NOT_EXISTS.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:modify signed credentialPojo content should verify fail.
     */
    @Test
    public void testAddSignature_modifySignContent() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        CredentialPojo doubleSigned = response.getResult();
        LogUtil.info(logger, "issuer null", response);
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        doubleSigned.setContext(credentialPojo.getContext().substring(0,9));
        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }

    /**
     * case14:modify credentialPojo content should verify fail.
     */
    @Test
    public void testAddSignature_modifyCredentialContent() {
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        List<CredentialPojo> credPojoList = new ArrayList<>();
        copyCredentialPojo.setContext(copyCredentialPojo.getContext().substring(0,10));
        credPojoList.add(copyCredentialPojo);
        credPojoList.add(credentialPojo);
        WeIdAuthentication callerAuth = TestBaseUtil.buildWeIdAuthentication(weid);

        ResponseData<CredentialPojo> response = credentialPojoService.addSignature(credPojoList,
            callerAuth);
        LogUtil.info(logger, "issuer null", response);

        CredentialPojo doubleSigned = response.getResult();
        Assert.assertEquals(doubleSigned.getCptId(),
            CredentialConstant.CREDENTIALPOJO_EMBEDDED_SIGNATURE_CPT);

        ResponseData<Boolean> verifyResp = credentialPojoService
            .verify(doubleSigned.getIssuer(), doubleSigned);
        LogUtil.info(logger, "verify signed credentialPojo", verifyResp);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verifyResp.getErrorCode().intValue());
    }
}

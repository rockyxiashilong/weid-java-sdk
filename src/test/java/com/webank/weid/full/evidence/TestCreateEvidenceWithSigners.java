package com.webank.weid.full.evidence;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.webank.weid.full.TestBaseUtil.createEcKeyPair;

import com.webank.weid.common.LogUtil;
import com.webank.weid.common.PasswordKey;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.EvidenceInfo;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

public class TestCreateEvidenceWithSigners extends TestBaseServcie {
    private static final Logger logger = LoggerFactory.getLogger(
        TestCreateEvidenceWithSigners.class);

    private static volatile Credential credential = null;
    private static volatile CredentialPojo credentialPojo = null;
    private static volatile CredentialPojo selectiveCredentialPojo = null;

    @Override
    public synchronized void testInit() {
        super.testInit();
        if (credential == null) {
            credential = super.createCredential(createCredentialArgs).getCredential();
        }
        if (credentialPojo == null) {
            credentialPojo = super.createCredentialPojo(createCredentialPojoArgs);
        }
        if (selectiveCredentialPojo == null) {
            selectiveCredentialPojo = this.createSelectiveCredentialPojo(credentialPojo);
        }
    }

    /**
     * case1: create evidence by credential success,the signers is only contain issuer weid.
     */
    @Test
    public void testCreateEvidenceByCredential_signalSigners() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        List<String> signers = new ArrayList<>(Arrays.asList(credential.getIssuer()));
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case2: create evidence by credential success,the signers is not contain issuer WeId.
     */
    @Test
    public void testCreateEvidenceByCredential_SignersNotContainIssuer() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResult);
        List<String> signers = new ArrayList<>();
        signers.add(createWeIdResult.getWeId());
        signers.add(super.createWeId().getWeId());
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case3: repeat create evidence by same credential success,but evidence is different,
     * the signers is only contain issuer weid.
     *
     */
    @Test
    public void testCreateEvidence_signalSignersRepeat() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        List<String> signers = new ArrayList<>(Arrays.asList(credential.getIssuer()));
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        ResponseData<String> createEvi = evidenceService.createEvidence(credential, signers,
            tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        Assert.assertNotEquals(response.getResult(), createEvi.getResult());
    }

    /**
     * case4: create evidence by credentialPojo success,the signers is only contain issuer weid.
     */
    @Test
    public void testCreateEvidenceByCredentialPojo_signalSigners() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        List<String> signers = new ArrayList<>(Arrays.asList(credential.getIssuer()));
        ResponseData<String> response = evidenceService
            .createEvidence(credentialPojo, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credentialPojo, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case5: create evidence by credentialPojo success,the signers is not contain issuer WeId.
     */
    @Test
    public void testCreateEvidenceByCredentialPojo_SignersNotContainIssuer() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResult);
        List<String> signers = new ArrayList<>();
        signers.add(createWeIdResult.getWeId());
        signers.add(super.createWeId().getWeId());
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case6: create evidence by selectiveCredentialPojo success,
     * the signers is only contain issuer weid.
     */
    @Test
    public void testCreateEvidenceBySelectiveCredentialPojo_signalSigners() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        List<String> signers = new ArrayList<>(Arrays.asList(credential.getIssuer()));
        ResponseData<String> response = evidenceService
            .createEvidence(selectiveCredentialPojo, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case7: create evidence by credential success,the signers is not contain issuer WeId.
     */
    @Test
    public void testCreateEvidenceBySelectiveCredentialPojo_SignersNotContainIssuer() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResult);
        List<String> signers = new ArrayList<>();
        signers.add(createWeIdResult.getWeId());
        signers.add(super.createWeId().getWeId());
        ResponseData<String> response = evidenceService
            .createEvidence(selectiveCredentialPojo, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(selectiveCredentialPojo, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case8: weIdPrivateKey is null.
     */
    @Test
    public void testCreateEvidence_priKeyNull() {
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService
            .createEvidence(credentialPojo, signers, null);
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(
            ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(!response.getResult().isEmpty());
    }

    /**
     * case9: privateKey is xxxxx.
     */
    @Test
    public void testCreateEvidence_privateKeyInvalid() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey().setPrivateKey("xxxxx");
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            credentialPojo, signers, tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);
        Assert.assertEquals(
            ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(!response.getResult().isEmpty());
    }

    /**
     * case10: privateKey is blank.
     */
    @Test
    public void testCreateEvidence_priKeyBlank() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey().setPrivateKey("");
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            credentialPojo, signers, tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);
        Assert.assertEquals(
            ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertFalse(!response.getResult().isEmpty());
    }

    /**
     * cas11: privateKey is not exist.
     */
    @Test
    public void testCreateEvidence_privateKeyNotExist() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        PasswordKey passwordKey = createEcKeyPair();
        WeIdPrivateKey weIdPrivateKey = new WeIdPrivateKey();
        weIdPrivateKey.setPrivateKey(passwordKey.getPrivateKey());
        List<String> signers =
            new ArrayList<>(Arrays.asList(tempCreateWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService
            .createEvidence(credentialPojo, signers, weIdPrivateKey);
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
    }

    /**
     * case13: credentialPojo id is null.
     */
    @Test
    public void testCreateEvidence_idNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setId(null);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertFalse(!response.getResult().isEmpty());
    }

    /**
     * case14: the cptId is null of credential.
     */
    @Test
    public void testCreateEvidence_cptIdNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setCptId(null);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case15: the cptId is not exist.
     */
    @Test
    public void testCreateEvidence_cptIdNotExist() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setCptId(999999999);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), eviInfo.getErrorCode().intValue());
        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case16: the cptId is minus.
     */
    @Test
    public void testCreateEvidence_cptIdIsMinus() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setCptId(-1);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case17: the issuer is null.
     */
    @Test
    public void testCreateEvidence_issuerIsNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuer(null);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case18: the issuer is blank.
     */
    @Test
    public void testCreateEvidence_issuerIsBlank() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuer("");
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case19: the issuer is not exist.
     */
    @Test
    public void testCreateEvidence_issuerNotExist() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuer("did:weid:101:0x39e5e6f663ef77409144014ceb063713b656ffff");
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case20: the issuer is not invalid.
     */
    @Test
    public void testCreateEvidence_issuerInvalid() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuer("did:weid:0x39e5e6f663ef77409144014ceb063713b656");
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case21: the claim is null.
     */
    @Test
    public void testCreateEvidence_claimNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setClaim(null);

        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));
        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case22: the claim is blank.
     */
    @Test
    public void testCreateEvidence_claimBlank() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setClaim(new HashMap<>());
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case23: the issuanceDate is minus.
     */
    @Test
    public void testCreateEvidence_issuanceDateIsMinus() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuanceDate(-1L);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case24: the expireDate is minus.
     */
    @Test
    public void testCreateEvidence_expireDateIsMinus() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setExpirationDate(-1L);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case25: the expireDate is null.
     */
    @Test
    public void testCreateEvidence_expireDateNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setIssuanceDate(null);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case26: the expireDate is passed.
     */
    @Test
    public void testCreateEvidence_expireDatePassed() {

        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        long expireDate = System.currentTimeMillis() - 10000;
        tempCredential.setIssuanceDate(expireDate);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
    }

    /**
     * case27: the pfooof is null.
     */
    @Test
    public void testCreateEvidence_proofNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setProof(null);
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case28: the proof is blank.
     */
    @Test
    public void testCreateEvidence_proofBlank() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        CredentialPojo tempCredential = copyCredentialPojo(credentialPojo);
        tempCredential.setProof(new HashMap<>());
        List<String> signers =
            new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId()));

        ResponseData<String> response = evidenceService.createEvidence(
            tempCredential, signers, createWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidence", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(tempCredential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case29: create evidence by credential success,the signers contains invalid weid.
     */
    @Test
    public void testCreateEvidenceByCredential_SignersContainsInvalidWeId() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResult);
        List<String> signers = new ArrayList<>();
        signers.add(createWeIdResult.getWeId());
        signers.add(super.createWeId().getWeId());
        signers.add("did:weid:101:1234");
        signers.add("010");
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                tempCreateWeIdResultWithSetAttr.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case30: create evidence by credential success,the signers contains 10+ duplicate weid.
     */
    @Test
    public void testCreateEvidenceByCredential_signersContainsDuplicateWeId() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr = null;
        List<String> signers = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            tempCreateWeIdResultWithSetAttr =
                super.copyCreateWeId(createWeIdResultWithSetAttr);
            signers.add(tempCreateWeIdResultWithSetAttr.getWeId());
        }
        signers.add(createWeIdResult.getWeId());
        System.out.println(signers);
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case31: create evidence by credential success,the signers contains 10+ weid.
     */
    @Test
    public void testCreateEvidenceByCredential_signersContainsManyWeId() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        List<String> signers = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String weid = tempCreateWeIdResultWithSetAttr.getWeId();
            signers.add(weid.substring(0, weid.length()-1)+i);
        }
        signers.add(tempCreateWeIdResultWithSetAttr.getWeId());
        signers.add(createWeIdResult.getWeId());
        System.out.println(signers);
        ResponseData<String> response = evidenceService
            .createEvidence(credential, signers,
                createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credential, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case32:when signers is null,create evidence success.
     */
    @Test
    public void testCreateEvidenceByCredential_signersNull() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        ResponseData<String> response = evidenceService
            .createEvidence(credentialPojo, null,
                createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credentialPojo, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case32:when signers is blank,create evidence success.
     */
    @Test
    public void testCreateEvidenceByCredential_signersBlank() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        ResponseData<String> response = evidenceService
            .createEvidence(credentialPojo, new ArrayList<>(),
                createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        //get evidence
        String eviAddr = response.getResult();
        ResponseData<EvidenceInfo> eviInfo = evidenceService.getEvidence(eviAddr);
        LogUtil.info(logger, "getEvidence", eviInfo);
        //Assert.assertEquals(signers.get(0), eviInfo.getResult().getSigners().get(0));

        //verify evidence
        ResponseData<Boolean> verifyInfo = evidenceService.verify(credentialPojo, eviAddr);
        LogUtil.info(logger, "verifyEvidence", verifyInfo);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), verifyInfo.getErrorCode().intValue());
    }

    /**
     * case33:when signers is a ,private key is b,then create evidence fail.
     */
    @Test
    public void testCreateEvidenceByCredential_signersNotMatchPrivateKey() {
        CreateWeIdDataResult tempCreateWeIdResultWithSetAttr =
            super.copyCreateWeId(createWeIdResultWithSetAttr);
        ResponseData<String> response = evidenceService.createEvidence(
            credentialPojo, new ArrayList<>(Arrays.asList(createWeIdResultWithSetAttr.getWeId())),
                createWeIdResult.getUserWeIdPrivateKey());
        LogUtil.info(logger, "createEvidenceWithSigners", response);

        Assert.assertEquals(ErrorCode.CREDENTIAL_PRIVATE_KEY_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
    }
}

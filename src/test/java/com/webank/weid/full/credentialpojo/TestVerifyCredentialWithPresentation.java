package com.webank.weid.full.credentialpojo;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.Challenge;
import com.webank.weid.protocol.base.ClaimPolicy;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.PresentationE;
import com.webank.weid.protocol.base.PresentationPolicyE;
import com.webank.weid.protocol.base.WeIdAuthentication;
import com.webank.weid.protocol.base.WeIdPrivateKey;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.request.CreateCredentialPojoArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.util.DataToolUtils;

public class TestVerifyCredentialWithPresentation extends TestBaseServcie {

    private static final Logger logger =
        LoggerFactory.getLogger(TestCreatePresentation.class);

    private static CredentialPojo credentialPojoNew = null;

    private static List<CredentialPojo> credentialList = new ArrayList<>();

    private static PresentationPolicyE presentationPolicyE
        = PresentationPolicyE.create("policy.json");

    private static Challenge challenge = null;

    private static PresentationE presentationE = null;

    @Override
    public synchronized void testInit() {
        super.testInit();

        if (credentialPojoNew == null) {
            credentialPojoNew = super.createCredentialPojo(createCredentialPojoArgsNew);
        }
        if (presentationPolicyE != null) {
            presentationPolicyE = PresentationPolicyE.create("policy.json");
            presentationPolicyE.setPolicyPublisherWeId(createWeIdResultWithSetAttr.getWeId());
            Map<Integer, ClaimPolicy> policyMap = presentationPolicyE.getPolicy();
            ClaimPolicy cliamPolicy = policyMap.get(1000);
            policyMap.remove(1000);
            policyMap.put(createCredentialPojoArgs.getCptId(), cliamPolicy);
        }
        if (challenge == null) {
            challenge = Challenge.create(
                createWeIdResultWithSetAttr.getWeId(),
                String.valueOf(System.currentTimeMillis()));
        }

        if (credentialList == null || credentialList.size() == 0) {
            credentialList.add(credentialPojo);
        }

        if (presentationE == null) {
            ResponseData<PresentationE> response = credentialPojoService.createPresentation(
                credentialList,
                presentationPolicyE,
                challenge,
                TestBaseUtil.buildWeIdAuthentication(createWeIdResultWithSetAttr)
            );
            Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
            presentationE = response.getResult();
        }

    }

    /**
     * verify credential pojo with presention successs.
     */

    @Test
    public void testVerfiyCredential_suceess() {

        ResponseData<Boolean> response = credentialPojoService.verify(
            credentialPojo.getIssuer(),
            presentationPolicyE,
            challenge,
            presentationE);
        LogUtil.info(logger, "testVerfiyCredentialWithPresention", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
    }

    /**
     * verify credential issuer is null.
     */

    @Test
    public void testVerfiyCredential_issuerNull() {

        ResponseData<Boolean> response = credentialPojoService.verify(
            null,
            presentationPolicyE,
            challenge,
            presentationE);
        LogUtil.info(logger, "testVerfiyCredentialWithPresention", response);
        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
    }

    @Test
    public void testVerfiyCredential_complexSuccess() throws IOException {

        //创建一个WeId
        CreateWeIdDataResult createWeId = super.createWeId();
        WeIdAuthentication weIdAuthentication = new WeIdAuthentication();
        weIdAuthentication.setWeId(createWeId.getWeId());
        weIdAuthentication.setWeIdPrivateKey(new WeIdPrivateKey());
        weIdAuthentication.getWeIdPrivateKey()
            .setPrivateKey(createWeId.getUserWeIdPrivateKey().getPrivateKey());
        weIdAuthentication.setWeIdPublicKeyId(createWeId.getUserWeIdPublicKey().getPublicKey());

        //注册cpt
        HashMap<String, Object> cptJsonSchemaData = new HashMap<String, Object>();
        JsonNode jsonNode = JsonLoader.fromResource("/cert.json");
        cptJsonSchemaData = DataToolUtils.deserialize(
            jsonNode.toString(),
            HashMap.class
        );
        System.out.println(cptJsonSchemaData);

        CptMapArgs cptMapArgs = new CptMapArgs();
        cptMapArgs.setCptJsonSchema(cptJsonSchemaData);
        cptMapArgs.setWeIdAuthentication(weIdAuthentication);
        CptBaseInfo cptBaseInfo = registerCpt(createWeId, cptMapArgs);
        System.out.println(cptBaseInfo);

        //生成claim
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("did", createWeId.getWeId());
        HashMap<String, Object> fullname = new HashMap<>();
        fullname.put("en", "rocky");
        fullname.put("cn", "龙");
        claim.put("fullname", fullname);
        HashMap<String, Object> cert = new HashMap<>();
        cert.put("code", "9527");
        cert.put("title", fullname);
        cert.put("category", fullname);
        cert.put("issueDate", "2021-01-18T10:11:11Z");
        claim.put("cert", cert);
        ArrayList<Object> issuers = new ArrayList<>();
        HashMap<String, Object> items = new HashMap<>();
        HashMap<String, Object> name = new HashMap<>();
        name.put("name", fullname);
        items.put("items", name);
        issuers.add(items);
        claim.put("issuers", issuers);
        CreateCredentialPojoArgs createCredentialArgs = new CreateCredentialPojoArgs();
        createCredentialArgs.setClaim(claim);
        System.out.println(claim);

        createCredentialArgs.setCptId(cptBaseInfo.getCptId());
        createCredentialArgs.setExpirationDate(
            System.currentTimeMillis() + (1000 * 60 * 60 * 24));
        createCredentialArgs.setIssuer(createWeId.getWeId());
        createCredentialArgs.setWeIdAuthentication(weIdAuthentication);
        System.out.println(createCredentialArgs.getClaim());

        //创建credentialPojo
        ResponseData<CredentialPojo> response =
            credentialPojoService.createCredential(createCredentialArgs);
        LogUtil.info(logger, "createCredentialPojo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());

        CredentialPojo credentialPojo = response.getResult();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);

        List<CredentialPojo> credentialPojoList = new ArrayList<>();
        credentialPojoList.add(credentialPojo);
        credentialPojoList.add(copyCredentialPojo);

        PresentationPolicyE presentationPolicyE = PresentationPolicyE.create("policy.json");
        presentationPolicyE.setPolicyPublisherWeId(createWeId.getWeId());
        Map<Integer, ClaimPolicy> policyMap = presentationPolicyE.getPolicy();
        ClaimPolicy cliamPolicy = policyMap.get(1000);
        cliamPolicy.setFieldsToBeDisclosed(
            "{\"did\" : 0,\"fullname\" : 1,\"cert\" : 0,\"issuers\": 1}");
        policyMap.remove(1000);
        policyMap.put(createCredentialArgs.getCptId(), cliamPolicy);

        challenge.setWeId(createWeId.getWeId());
        ResponseData<PresentationE> response1 = credentialPojoService.createPresentation(
            credentialPojoList,
            presentationPolicyE,
            challenge,
            weIdAuthentication
        );
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response1.getErrorCode().intValue());
        PresentationE presentationE = response1.getResult();

        ResponseData<Boolean> verify = credentialPojoService.verify(
            createWeId.getWeId(),
            presentationPolicyE,
            challenge,
            presentationE);
        LogUtil.info(logger, "testVerfiyCredentialWithPresention", verify);
        Assert.assertEquals(ErrorCode.CREDENTIAL_ISSUER_MISMATCH.getCode(),
            verify.getErrorCode().intValue());



    }


}

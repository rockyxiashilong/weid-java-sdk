package com.webank.weid.full.transportation;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import mockit.Mock;
import mockit.MockUp;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.protocol.base.Credential;
import com.webank.weid.protocol.base.CredentialPojo;
import com.webank.weid.protocol.base.PresentationE;
import com.webank.weid.protocol.response.ResponseData;
import com.webank.weid.suite.api.transportation.TransportationFactory;
import com.webank.weid.suite.api.transportation.params.EncodeType;
import com.webank.weid.suite.api.transportation.params.ProtocolProperty;
import com.webank.weid.suite.crypto.CryptService;
import com.webank.weid.suite.crypto.CryptServiceFactory;
import com.webank.weid.suite.entity.CryptType;
import com.webank.weid.util.DataToolUtils;

/**
 * test serialize class.
 */
public class TestPdfSerialize extends TestBaseTransportation {

    private static final Logger logger = LoggerFactory.getLogger(TestPdfSerialize.class);
    private static CredentialPojo credentialPojo = null;
    private static CredentialPojo credentialPojoNew = null;
    private static volatile CredentialPojo selectiveCredentialPojo = null;
    private static volatile Credential credential = null;
    private static PresentationE presentation;
    private static PresentationE presentation4MlCpt;
    private static PresentationE presentation4MultiCpt;
    private static PresentationE presentation4SpecTpl;


    @Override
    public synchronized void testInit() {
        super.testInit();
        super.testInit4MlCpt();
        super.testInit4MultiCpt();
        super.testInitSpecTplCpt();
        if (credentialPojo == null) {
            credentialPojo = super.createCredentialPojo(createCredentialPojoArgs);
        }
        if (credentialPojoNew == null) {
            credentialPojoNew = super.createCredentialPojo(createCredentialPojoArgsNew);
        }
        if (selectiveCredentialPojo == null) {
            selectiveCredentialPojo = this.createSelectiveCredentialPojo(credentialPojo);
        }
        if (credential == null) {
            credential = super.createCredential(createCredentialArgs)
                .getCredential();
        }

        mockMysqlDriver();
        presentation = getPresentationE();
        presentation4MlCpt = getPresentationE4MlCpt();
        presentation4MultiCpt = getPresentationE4MultiCpt();
        presentation4SpecTpl = getPresentationE4SpecTplCpt();
    }


    /**
     * 单级CPT测试.
     */
    @Test
    public void testSerialize_signalCptPolicy() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }


    /**
     * 多级CPT测试.
     */
    @Test
    public void testSerializeCase2() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4MlCpt,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);
        LogUtil.info(logger, "presentiation", presentation4MlCpt);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * biggest length test.
     */
    @Test
    public void testSerialize_biggestLength() {
        PresentationE copyPresention = DataToolUtils.clone(presentation4MlCpt);
        List<CredentialPojo> credentialPojoList = copyPresention.getVerifiableCredential();
        CredentialPojo credentialPojo = credentialPojoList.size()==1
            ? credentialPojoList.get(0):credentialPojoNew;
        for (int i = 0; i < 5; i++) {
            credentialPojoList.add(credentialPojo);
        }
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresention,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        //Deserialize
        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation().deserialize(response.getResult(), PresentationE.class,
                 weIdAuthentication);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(copyPresention.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 修改 presentation，设置其中的credentialPojo为空，序列化成功，但是文件打不开.
     */
    @Ignore
    @Test
    public void testSerialize_credentialPojoIsNull() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        credentialPojoList.remove(0);
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，设置为两个重复的credentialPojo，序列化成功.
     */
    @Test
    public void testSerialize_credentialPojoDouble() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo credentialPojo = credentialPojoList.get(0);
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，设置为两个不同的credentialPojo，序列化成功.
     */
    @Test
    public void testSerialize_credentialPojoDifferent() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        credentialPojoList.add(credentialPojoNew);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，credentialPojo中的claim为null，序列化成功.
     */
    @Test
    public void testSerialize_credentialPojoClaimNull() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        copyCredentialPojo.setClaim(new HashMap<>());
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，修改credentialPojo中的claim的name值，序列化成功.
     */
    @Test
    public void testSerialize_modifyClaimValue() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> claim = copyCredentialPojo.getClaim();
        claim.replace("name", "rockyxia");
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，增加credentialPojo中的claim新的键值对，序列化成功.
     */
    @Test
    public void testSerialize_addClaimValue() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> claim = copyCredentialPojo.getClaim();
        claim.put("company", "webank");
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation，删除credentialPojo中的claim新的键值对，序列化成功.
     */
    @Test
    public void testSerialize_delClaimValue() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        Map<String, Object> claim = copyCredentialPojo.getClaim();
        claim.remove("name");
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation.content值，序列化成功.
     */
    @Test
    public void testSerialize_modifyContent() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<String> content = new ArrayList<>();
        copyPresentationE.setContext(content);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation.proof为null值，序列化成功.
     */
    @Test
    public void testSerialize_setProoofNull() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        Map<String, Object> proof = new HashMap<>();
        copyPresentationE.setProof(proof);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 修改 presentation.credentialPojo.proof为null值，序列化成功.
     */
    @Test
    public void testSerialize_setCredentialPojoProoofNull() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);
        List<CredentialPojo> credentialPojoList =  copyPresentationE.getVerifiableCredential();
        CredentialPojo copyCredentialPojo = copyCredentialPojo(credentialPojo);
        copyCredentialPojo.setProof(new HashMap<>());
        credentialPojoList.add(copyCredentialPojo);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 序列化credentialPojo，序列化成功.
     */
    @Test
    public void testSerialize_credentialPojo() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                credentialPojoNew,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 序列化selectiveCredentialPojo，序列化成功.
     */
    @Test
    public void testSerialize_selectiveCredentialPojo() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                selectiveCredentialPojo,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 序列化selectiveCredentialPojo，序列化成功.
     */
    @Test
    public void testSerialize_credential() {

        List<CredentialPojo> credPojoList = new ArrayList<>();
        credPojoList.add(selectiveCredentialPojo);
        CredentialPojo doubleSigned =
            credentialPojoService.addSignature(credPojoList, weIdAuthentication)
            .getResult();
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                doubleSigned,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 多CPT测试.
     */
    @Test
    public void testSerializeCase3() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(presentation4MultiCpt,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 使用密文方式构建协议数据.
     */
    @Test
    public void testSerializeCase4() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation().specify(verifier)
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.CIPHER),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * 传入协议配置编解码方式为null.
     */
    @Test
    public void testSerializeCase5() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(presentation,
                new ProtocolProperty(null),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_PROTOCOL_ENCODE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }


    /**
     * 传入的协议配置为null.
     */
    @Test
    public void testSerializeCase6() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation,
                null,
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_PROTOCOL_PROPERTY_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * 传入presentation为null.
     */
    @Test
    public void testSerializeCase7() {
        PresentationE presentation = null;
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_PROTOCOL_DATA_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * 传入weIdAuthentication为null.
     */
    @Test
    public void testSerializeCase8() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.ORIGINAL),
                null);
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.WEID_AUTHORITY_INVALID.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * 指定PDF模板测试.
     */
    @Test
    public void testSerializeCase9() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4SpecTpl,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication,
                "src/test/resources/test-template.pdf"
                );
        System.out.println(presentation4SpecTpl.toJson());
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.SUCCESS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }


    /**
     * 传入指定模板目录为空字符串.
     */
    @Test
    public void testSerializeCase10() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4SpecTpl,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication,
                ""
                );
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.ILLEGAL_INPUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * 传入指定模板目录为非法字符串.
     */
    @Test
    public void testSerializeCase11() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4SpecTpl,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication,
                "illegal"
                );
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * mock异常情况.
     */
    @Test
    public void testSerializeCase12() {

        MockUp<CryptServiceFactory> mockTest = new MockUp<CryptServiceFactory>() {
            @Mock
            public CryptService getCryptService(CryptType cryptType) {
                return new HashMap<String, CryptService>().get("key");
            }
        };

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .specify(verifier)
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.CIPHER),
                weIdAuthentication);
        mockTest.tearDown();
        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_ENCODE_BASE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }
}

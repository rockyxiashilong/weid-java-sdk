package com.webank.weid.full.transportation;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;

import com.sun.xml.internal.fastinfoset.tools.FI_DOM_Or_XML_DOM_SAX_SAXEvent;
import mockit.Mock;
import mockit.MockUp;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
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
 * test base class.
 */
public class TestPdfDeserialize extends TestBaseTransportation {

    private static final Logger logger = LoggerFactory.getLogger(TestPdfDeserialize.class);

    private static PresentationE presentation;
    private static PresentationE presentation4MlCpt;
    private static PresentationE presentation4MultiCpt;
    private static PresentationE presentation4SpecTpl;
    private static CredentialPojo credentialPojoNew;

    @Override
    public synchronized void testInit() {
        if (presentation == null) {
            super.testInit();
            super.testInit4MlCpt();
            super.testInit4MultiCpt();
            super.testInitSpecTplCpt();
            mockMysqlDriver();
            if (credentialPojoNew == null) {
                credentialPojoNew = super.createCredentialPojo(createCredentialPojoArgsNew);
            }
            presentation = this.getPresentationE();
            presentation4MlCpt = getPresentationE4MlCpt();
            presentation4MultiCpt = getPresentationE4MultiCpt();
            presentation4SpecTpl = getPresentationE4SpecTplCpt();
        }
    }

    /**
     * 使用原文方式构建协议数据并解析.
     */
    @Test
    public void testDeserializeCase1() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation,
                new ProtocolProperty((EncodeType.ORIGINAL)),
                weIdAuthentication);

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(
                response.getResult(),
                PresentationE.class,
                weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(presentation.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 使用密文方式构建协议数据并解析.
     */
    @Test
    public void testDeserializeCase2() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .specify(verifier)
            .serialize(
                presentation4MlCpt,
                new ProtocolProperty((EncodeType.CIPHER)),
                weIdAuthentication);

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(
                response.getResult(),
                PresentationE.class,
                weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(presentation4MlCpt.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 未设置verifier导致的无权限获取密钥数据.
     */
    @Test
    public void testDeserializeCase3() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4MlCpt,
                new ProtocolProperty((EncodeType.CIPHER)),
                weIdAuthentication);

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(
                response.getResult(),
                PresentationE.class,
                weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.ENCRYPT_KEY_NO_PERMISSION.getCode(),
            resDeserialize.getErrorCode().intValue());
    }

    /**
     * 对指定PDF模板序列化并解析.
     */
    @Test
    public void testDeserializeCase4() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                presentation4SpecTpl,
                new ProtocolProperty((EncodeType.ORIGINAL)),
                weIdAuthentication,
                "src/test/resources/test-template.pdf");

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(
                response.getResult(),
                PresentationE.class,
                weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(presentation4SpecTpl.toJson(), resDeserialize.getResult().toJson());
    }


    /**
     * 输入流数据为空.
     */
    @Test
    public void testDeserializeCase5() {
        OutputStream out = null;
        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(out, PresentationE.class, weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR.getCode(),
            resDeserialize.getErrorCode().intValue());
        Assert.assertNull(resDeserialize.getResult());
    }

    /**
     * 输入流数据非法.
     */
    @Test
    public void testDeserializeCase6() {
        OutputStream out = new ByteArrayOutputStream();
        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(out, PresentationE.class, weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.TRANSPORTATION_PDF_TRANSFER_ERROR.getCode(),
            resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(null, resDeserialize.getResult());
    }

    /**
     * mock异常情况.
     */
    @Test
    public void testDeserializeCase7() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .specify(verifier)
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.CIPHER),
                weIdAuthentication
            );

        MockUp<CryptServiceFactory> mockTest = new MockUp<CryptServiceFactory>() {
            @Mock
            public CryptService getCryptService(CryptType cryptType) {
                return new HashMap<String, CryptService>().get("key");
            }
        };

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(response.getResult(), PresentationE.class, weIdAuthentication);
        mockTest.tearDown();
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_ENCODE_BASE_ERROR.getCode(),
            resDeserialize.getErrorCode().intValue()
        );
        Assert.assertNull(resDeserialize.getResult());
    }

    /**
     * mock异常情况.
     */
    @Test
    public void testDeserializeCase8() {
        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .specify(verifier)
            .serialize(
                presentation,
                new ProtocolProperty(EncodeType.CIPHER),
                weIdAuthentication);

        MockUp<EncodeType> mockTest = new MockUp<EncodeType>() {
            @Mock
            public EncodeType getObject(String value) {
                return null;
            }
        };

        ResponseData<PresentationE> resDeserialize = TransportationFactory
            .newPdfTransportation()
            .deserialize(response.getResult(), PresentationE.class, weIdAuthentication);
        mockTest.tearDown();
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(
            ErrorCode.TRANSPORTATION_PROTOCOL_ENCODE_ERROR.getCode(),
            resDeserialize.getErrorCode().intValue()
        );
        Assert.assertNull(resDeserialize.getResult());
    }

    /**
     * credentialPojo测试.
     */
    @Test
    public void testDeserializeCase9() {
        List<CredentialPojo> credentialPojoList = presentation.getVerifiableCredential();
        CredentialPojo credentialPojo = new CredentialPojo();
        if (credentialPojoList.size() > 0) {
            credentialPojo = credentialPojoList.get(0);
        }

        ResponseData<OutputStream> response =
                TransportationFactory.newPdfTransportation().serialize(
                        credentialPojo,
                        new ProtocolProperty(EncodeType.CIPHER),
                        weIdAuthentication
                );
        ResponseData<PresentationE> resDeserialize = TransportationFactory.newPdfTransportation()
                .deserialize(
                        response.getResult(),
                        PresentationE.class,
                        weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.ENCRYPT_KEY_NO_PERMISSION.getCode(),
                resDeserialize.getErrorCode().intValue());
    }

    /**
     * credentialPojo反序列化测试.
     */
    @Test
    public void testDeserialize_credentialPojo() {
        List<CredentialPojo> credentialPojoList = presentation.getVerifiableCredential();
        CredentialPojo credentialPojo = new CredentialPojo();
        if (credentialPojoList.size() > 0) {
            credentialPojo = credentialPojoList.get(0);
        }

        ResponseData<OutputStream> response =
            TransportationFactory.newPdfTransportation().serialize(
                credentialPojo,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication
            );
        ResponseData<CredentialPojo> resDeserialize = TransportationFactory.newPdfTransportation()
            .deserialize(
                response.getResult(),
                CredentialPojo.class,
                weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(),
            resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(credentialPojo.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 修改 presentation，设置为两个重复的credentialPojo，序列化成功，然后反序列化成功
     */
    @Test
    public void testDeserialize_credentialPojoDouble() {
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

        //Deserialize
        ResponseData<PresentationE> resDeserialize =
            TransportationFactory.newPdfTransportation().deserialize(response.getResult(),
                PresentationE.class, weIdAuthentication);
        LogUtil.info(logger, "deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(copyPresentationE.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 修改 presentation，设置为两个不同的credentialPojo，序列化成功，然后反序列化.
     */
    @Test
    public void testDeserialize_credentialPojoDifferent() {
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

        //Deserialize

        ResponseData<PresentationE> resDeserialize =
            TransportationFactory.newPdfTransportation().deserialize(response.getResult(),
                PresentationE.class, weIdAuthentication);
        LogUtil.info(logger, "Deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(copyPresentationE.toJson(), resDeserialize.getResult().toJson());
    }

    /**
     * 修改 presentation，设置为两个不同的credentialPojo，序列化成功，然后反序列化.
     */
    @Test
    public void testDeserialize_output() {
        PresentationE copyPresentationE = DataToolUtils.clone(presentation);

        ResponseData<OutputStream> response = TransportationFactory
            .newPdfTransportation()
            .serialize(
                copyPresentationE,
                new ProtocolProperty(EncodeType.ORIGINAL),
                weIdAuthentication);

        LogUtil.info(logger, "serialize", response);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        //Deserialize
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        File file = new File("tmp.pdf");
        PDDocument document = null;
        try {
            document = PDDocument.load(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            document.save(out);
        } catch (IOException e) {
            e.printStackTrace();
        }
        ResponseData<PresentationE> resDeserialize =
            TransportationFactory.newPdfTransportation().deserialize(out,
                PresentationE.class, weIdAuthentication);
        LogUtil.info(logger, "Deserialize", resDeserialize);
        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), resDeserialize.getErrorCode().intValue());
        Assert.assertEquals(copyPresentationE.toJson(), resDeserialize.getResult().toJson());
    }
}

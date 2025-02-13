/*
 *       Copyright© (2018-2019) WeBank Co., Ltd.
 *
 *       This file is part of weid-java-sdk.
 *
 *       weid-java-sdk is free software: you can redistribute it and/or modify
 *       it under the terms of the GNU Lesser General Public License as published by
 *       the Free Software Foundation, either version 3 of the License, or
 *       (at your option) any later version.
 *
 *       weid-java-sdk is distributed in the hope that it will be useful,
 *       but WITHOUT ANY WARRANTY; without even the implied warranty of
 *       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *       GNU Lesser General Public License for more details.
 *
 *       You should have received a copy of the GNU Lesser General Public License
 *       along with weid-java-sdk.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.webank.weid.full.auth;

import java.util.List;
import java.util.concurrent.Future;

import mockit.Mock;
import mockit.MockUp;
import org.bcos.web3j.abi.datatypes.Address;
import org.bcos.web3j.abi.datatypes.Type;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.contract.v1.AuthorityIssuerController;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.AuthorityIssuer;
import com.webank.weid.protocol.request.RemoveAuthorityIssuerArgs;
import com.webank.weid.protocol.response.CreateWeIdDataResult;
import com.webank.weid.protocol.response.ResponseData;

/**
 * queryAuthorityIssuerInfo method for testing AuthorityIssuerService.
 *
 * @author v_wbgyang
 */
public class TestQueryAuthorityIssuerInfo extends TestBaseServcie {

    private static final Logger logger =
        LoggerFactory.getLogger(TestQueryAuthorityIssuerInfo.class);

    private static CreateWeIdDataResult createWeId;

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (createWeId == null) {
            createWeId = super.registerAuthorityIssuer();
        }
    }

    /**
     * case: query success.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase1() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is blank.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase2() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(null);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is bad format.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase3() {

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo("xx:xx:xxxxxxx");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.WEID_INVALID.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is not exists.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase4() {

        ResponseData<AuthorityIssuer> response = authorityIssuerService
            .queryAuthorityIssuerInfo("did:weid:0xc7e399b8d2da337f4e92eb33ca88b60b899b5022");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is registed by other.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase5() {

        ResponseData<AuthorityIssuer> response = authorityIssuerService
            .queryAuthorityIssuerInfo("did:weid:0x5f3d8234e93823fac7ebdf0cfaa03b6a43d8773b");
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: WeIdentity DID is removed.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase6() {

        CreateWeIdDataResult createWeId = super.registerAuthorityIssuer();
        LogUtil.info(logger, "registerAuthorityIssuer", createWeId);

        RemoveAuthorityIssuerArgs removeAuthorityIssuerArgs =
            TestBaseUtil.buildRemoveAuthorityIssuerArgs(createWeId, privateKey);

        ResponseData<Boolean> response =
            authorityIssuerService.removeAuthorityIssuer(removeAuthorityIssuerArgs);
        LogUtil.info(logger, "removeAuthorityIssuer", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertEquals(true, response.getResult());

        ResponseData<AuthorityIssuer> response1 =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_CONTRACT_ERROR_NOT_EXISTS.getCode(),
            response1.getErrorCode().intValue());
        Assert.assertNull(response1.getResult());
    }

    /**
     * case: mock an InterruptedException.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase7() {

        MockUp<Future<?>> mockFuture = mockInterruptedFuture();

        ResponseData<AuthorityIssuer> response = queryAuthorityIssuerInfoForMock(mockFuture);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.TRANSACTION_EXECUTE_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: mock an TimeoutException.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase8() {

        final MockUp<Future<?>> mockFuture = mockTimeoutFuture();

        ResponseData<AuthorityIssuer> response = queryAuthorityIssuerInfoForMock(mockFuture);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.TRANSACTION_TIMEOUT.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /**
     * case: mock returns null when invoking the future.get().
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase9() {

        final MockUp<Future<?>> mockFuture = mockReturnNullFuture();

        ResponseData<AuthorityIssuer> response = queryAuthorityIssuerInfoForMock(mockFuture);
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    private ResponseData<AuthorityIssuer> queryAuthorityIssuerInfoForMock(
        MockUp<Future<?>> mockFuture) {

        MockUp<AuthorityIssuerController> mockTest = new MockUp<AuthorityIssuerController>() {
            @Mock
            public Future<?> getAuthorityIssuerInfoNonAccValue(Address addr) {
                return mockFuture.getMockInstance();
            }
        };

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        mockTest.tearDown();
        mockFuture.tearDown();
        return response;
    }

    /**
     * case: mock an NullPointerException.
     */
    @Test
    public void testQueryAuthorityIssuerInfoCase10() {

        MockUp<AuthorityIssuerController> mockTest = new MockUp<AuthorityIssuerController>() {
            @Mock
            public Future<List<Type<?>>> getAuthorityIssuerInfoNonAccValue(Address addr) {
                return null;
            }
        };

        ResponseData<AuthorityIssuer> response =
            authorityIssuerService.queryAuthorityIssuerInfo(createWeId.getWeId());
        LogUtil.info(logger, "queryAuthorityIssuerInfo", response);

        mockTest.tearDown();

        Assert.assertEquals(ErrorCode.AUTHORITY_ISSUER_ERROR.getCode(),
            response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }
}

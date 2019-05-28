/*
 *       Copyright© (2018) WeBank Co., Ltd.
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

package com.webank.weid.full.cpt;

import java.math.BigInteger;
import java.util.List;

import org.fisco.bcos.web3j.protocol.core.RemoteCall;
import org.fisco.bcos.web3j.tuples.generated.Tuple7;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.webank.weid.common.LogUtil;
import com.webank.weid.constant.ErrorCode;
import com.webank.weid.contract.CptController;
import com.webank.weid.full.TestBaseServcie;
import com.webank.weid.full.TestBaseUtil;
import com.webank.weid.protocol.base.Cpt;
import com.webank.weid.protocol.base.CptBaseInfo;
import com.webank.weid.protocol.request.CptMapArgs;
import com.webank.weid.protocol.response.ResponseData;

import mockit.Mock;
import mockit.MockUp;

/**
 * queryCpt method for testing CptService.
 * 
 * @author v_wbgyang
 *
 */
public class TestQueryCpt extends TestBaseServcie {
    
    private static final Logger logger = LoggerFactory.getLogger(TestQueryCpt.class);

    @Override
    public synchronized void testInit() {

        super.testInit();
        if (cptBaseInfo == null) {
            cptBaseInfo = super.registerCpt(createWeIdResultWithSetAttr);
        }
    }

    /** 
     * case： cpt query success .
     */
    @Test
    public void testQueryCptCase1() {

        ResponseData<Cpt> response = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());
    }

    /** 
     * case： cptId is null.
     */
    @Test
    public void testQueryCptCase2() {

        ResponseData<Cpt> response = cptService.queryCpt(null);
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptId is minus number.
     */
    @Test
    public void testQueryCptCase3() {

        ResponseData<Cpt> response = cptService.queryCpt(-1);
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(ErrorCode.ILLEGAL_INPUT.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： cptId is not exists.
     */
    @Test
    public void testQueryCptCase4() {

        ResponseData<Cpt> response = cptService.queryCpt(999999999);
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(ErrorCode.CPT_NOT_EXISTS.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }

    /** 
     * case： query after updateCpt.
     */
    @Test
    public void testQueryCptCase5() {

        ResponseData<Cpt> response = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "queryCpt", response);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), response.getErrorCode().intValue());
        Assert.assertNotNull(response.getResult());

        CptMapArgs cptMapArgs = TestBaseUtil.buildCptArgs(createWeIdNew);

        ResponseData<CptBaseInfo> responseUp = cptService.updateCpt(
            cptMapArgs,
            cptBaseInfo.getCptId());
        LogUtil.info(logger, "updateCpt", responseUp);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), responseUp.getErrorCode().intValue());
        Assert.assertNotNull(responseUp.getResult());

        ResponseData<Cpt> responseQ = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "queryCpt", responseQ);

        Assert.assertEquals(ErrorCode.SUCCESS.getCode(), responseQ.getErrorCode().intValue());
        Assert.assertNotNull(responseQ.getResult());
    }

    /**
     * case: mock returns null.
     */
    @Test
    public void testQueryCptCase7() {

        MockUp<CptController> mockTest = new MockUp<CptController>() {
            @Mock
            public RemoteCall<Tuple7<
	            String, 
	            List<BigInteger>, 
	            List<byte[]>, 
	            List<byte[]>, 
	            BigInteger, 
	            byte[], 
	            byte[]>
            > queryCpt(BigInteger cptId) {
            return null;
            }   
        };

        ResponseData<Cpt> response = cptService.queryCpt(cptBaseInfo.getCptId());
        LogUtil.info(logger, "queryCpt", response);
 
        mockTest.tearDown();

        Assert.assertEquals(ErrorCode.UNKNOW_ERROR.getCode(), response.getErrorCode().intValue());
        Assert.assertNull(response.getResult());
    }
}

#!/usr/bin/env sh

if [ "$TRAVIS_BRANCH" = "master" ];then
    echo "This is a master branch PR, starting build-tools CI pipeline.."
    # clone repo
    rm -rf weid-build-tools/
    git clone https://github.com/WeBankFinTech/weid-build-tools.git

    # construct SDK jar version and file name
    cat build.gradle | grep "version =" > temp.ver
    sed -e "s/version = \"//g" -i temp.ver
    sed -e "s/\"//g" -i temp.ver
    SDKVER=$(cat temp.ver)
    rm temp.ver
    SDKNAME='weid-java-sdk-'
    JAR='.jar'
    FILENAME="$SDKNAME$SDKVER$JAR"
    echo sdk jar filename: $FILENAME

    # copy SDK jar to repo dependencies path and rename
    # requires repo to allow local dep first
    # cp dist/app/$FILENAME weid-build-tools/dependencies/weid-java-sdk-pipeline.jar

    # install fisco-solc
    wget https://github.com/FISCO-BCOS/fisco-solc/raw/master/fisco-solc-ubuntu
    sudo cp fisco-solc-ubuntu /usr/bin/fisco-solc
    sudo chmod +x /usr/bin/fisco-solc

    # copy blockchain cfg files
    cp src/main/resources/ca.crt weid-build-tools/resources/
    cp src/main/resources/client.keystore weid-build-tools/resources/

    # run repo ci scripts
    cd weid-build-tools/
    sed -i -e '$a\org_id=test' run.config
    sed -i -e '$a\blockchain_address=$NODE_IP' run.config
    chmod +x compile.sh
    ./compile.sh
    ./deploy.sh
else
    echo "This is not a master branch PR (commit omitted). CI skipped."
fi
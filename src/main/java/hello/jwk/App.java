package hello.jwk;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.Use;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class App {
    private static final String AZURE_PUBLIC_KEY = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"piVlloQDSMKxh1m2ygqGSVdgFpA\",\"x5t\":\"piVlloQDSMKxh1m2ygqGSVdgFpA\",\"n\":\"0XhhwpmEpN-jDBapnzhFbtvEU2BpLLcaLzlXm4mlT2MwKZlXRUUam2vI0URDUYRKaa4O62BCWSSGOv2LGQ6tMD5oU-Dqkuf44bo1hLufIqAALUymssfRurTrLd0fqVA9ZCF3fA8_7xQi5r370m4h-G71ez8eE3lxiVPlwSeJXRpa5QzGA8ApwbXGiV-6liGU4eMXBU39A5rFy6TdioaC4P6xns-IdwlLMWdOR28P4O0yhbVTqcN_kW4N4AQonslB_tGOJGhWJjFkcqsQ8cbiJn6Q6FXoNADXohJO3sAtdUHyBNMXc68i25uTYTe_qyCKuC290TkyR3gxMlw7rtuB1Q\",\"e\":\"AQAB\",\"x5c\":[\"MIIDBTCCAe2gAwIBAgIQMCJcgWf4l5xPpeoEwB7DKDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTExNTAwMDAwMFoXDTI0MTExNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANF4YcKZhKTfowwWqZ84RW7bxFNgaSy3Gi85V5uJpU9jMCmZV0VFGptryNFEQ1GESmmuDutgQlkkhjr9ixkOrTA+aFPg6pLn+OG6NYS7nyKgAC1MprLH0bq06y3dH6lQPWQhd3wPP+8UIua9+9JuIfhu9Xs/HhN5cYlT5cEniV0aWuUMxgPAKcG1xolfupYhlOHjFwVN/QOaxcuk3YqGguD+sZ7PiHcJSzFnTkdvD+DtMoW1U6nDf5FuDeAEKJ7JQf7RjiRoViYxZHKrEPHG4iZ+kOhV6DQA16ISTt7ALXVB8gTTF3OvItubk2E3v6sgirgtvdE5Mkd4MTJcO67bgdUCAwEAAaMhMB8wHQYDVR0OBBYEFEXiTeLGkA2LgAjQOrT2KChpgwCgMA0GCSqGSIb3DQEBCwUAA4IBAQA6GqtYZDQzym0yxfL2NnlSbJP/lLhSQOqbPBdN6DWQ/3duk+e08Ix5qy63hzW+qQR0PAkFEcooL5+bdheS66tFJpVejEcqCSKUVvwOUe6GY/ju752dlB7anBB9An362khehCxqydYNS5Igl0rtcP7dKC3ZBn1m2B9ULsyx46iNpfHQHHv9NKU2vVq2CtNc95CFktwjUwlyWMgbfI/DzPX/cC6KnglqsuVVBO7+jIaBmi0XGqudooZkqgIrvnfNMM13Gy78TUNHsCiAQEwZ/L17yNbzotNGxAoPfuXldbD52MQNOsA7WhH+j8qFWY6gZzTN4NpVtuW4m04TCEFexnTz\"]}";
    private static final String AWS_PUBLIC_KEY = "{\"kty\":\"RSA\",\"alg\":\"RS512\",\"use\":\"sig\",\"kid\":\"ap-northeast-11\",\"n\":\"AI7mc1assO5n6yB4b7jPCFgVLYPSnwt4qp2BhJVAmlXRntRZ5w4910oKNZDOr4fe/BWOI2Z7upUTE/ICXdqirEkjiPbBN/duVy5YcHsQ5+GrxQ/UbytNVN/NsFhdG8W31lsE4dnrGds5cSshLaohyU/aChgaIMbmtU0NSWQ+jwrW8q1PTvnThVQbpte59a0dAwLeOCfrx6kVvs0Y7fX7NXBbFxe8yL+JR3SMJvxBFuYC+/om5EIRIlRexjWpNu7gJnaFFwbxCBNwFHahcg5gdtSkCHJy8Gj78rsgrkEbgoHk29pk8jUzo/O/GuSDGw8qXb6w0R1+UsXPYACOXM8C8+E=\",\"e\":\"AQAB\"}";

    public static void main(String[] args) throws Exception {
        final String fileName = "src/main/resources/keystore.jks";
        final char[] storePass = "foo-keystore-pwd".toCharArray();
        final String alias = "foo-domain";
        final String keyPass = "foo-key-pwd";
        final KeyStore store = KeyStore.getInstance("JKS");
        final InputStream input = new FileInputStream(fileName);
        store.load(input, storePass);
        final Certificate certificate = store.getCertificate(alias);
        final RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        final RSAPrivateKey privateKey = (RSAPrivateKey) store.getKey(alias, keyPass.toCharArray());

        final RSAKey jwk = new RSAKey(publicKey, privateKey, Use.SIGNATURE, null, "foo-kid");

        final RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
        final RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

        final RSAKey azureJwk = RSAKey.parse(AZURE_PUBLIC_KEY);
        final RSAKey awsJwk = RSAKey.parse(AWS_PUBLIC_KEY);
    }
}

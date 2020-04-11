package hello.jwk;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class App {
    private static final String AZURE_PUBLIC_KEY = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"piVlloQDSMKxh1m2ygqGSVdgFpA\",\"x5t\":\"piVlloQDSMKxh1m2ygqGSVdgFpA\",\"n\":\"0XhhwpmEpN-jDBapnzhFbtvEU2BpLLcaLzlXm4mlT2MwKZlXRUUam2vI0URDUYRKaa4O62BCWSSGOv2LGQ6tMD5oU-Dqkuf44bo1hLufIqAALUymssfRurTrLd0fqVA9ZCF3fA8_7xQi5r370m4h-G71ez8eE3lxiVPlwSeJXRpa5QzGA8ApwbXGiV-6liGU4eMXBU39A5rFy6TdioaC4P6xns-IdwlLMWdOR28P4O0yhbVTqcN_kW4N4AQonslB_tGOJGhWJjFkcqsQ8cbiJn6Q6FXoNADXohJO3sAtdUHyBNMXc68i25uTYTe_qyCKuC290TkyR3gxMlw7rtuB1Q\",\"e\":\"AQAB\",\"x5c\":[\"MIIDBTCCAe2gAwIBAgIQMCJcgWf4l5xPpeoEwB7DKDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MTExNTAwMDAwMFoXDTI0MTExNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANF4YcKZhKTfowwWqZ84RW7bxFNgaSy3Gi85V5uJpU9jMCmZV0VFGptryNFEQ1GESmmuDutgQlkkhjr9ixkOrTA+aFPg6pLn+OG6NYS7nyKgAC1MprLH0bq06y3dH6lQPWQhd3wPP+8UIua9+9JuIfhu9Xs/HhN5cYlT5cEniV0aWuUMxgPAKcG1xolfupYhlOHjFwVN/QOaxcuk3YqGguD+sZ7PiHcJSzFnTkdvD+DtMoW1U6nDf5FuDeAEKJ7JQf7RjiRoViYxZHKrEPHG4iZ+kOhV6DQA16ISTt7ALXVB8gTTF3OvItubk2E3v6sgirgtvdE5Mkd4MTJcO67bgdUCAwEAAaMhMB8wHQYDVR0OBBYEFEXiTeLGkA2LgAjQOrT2KChpgwCgMA0GCSqGSIb3DQEBCwUAA4IBAQA6GqtYZDQzym0yxfL2NnlSbJP/lLhSQOqbPBdN6DWQ/3duk+e08Ix5qy63hzW+qQR0PAkFEcooL5+bdheS66tFJpVejEcqCSKUVvwOUe6GY/ju752dlB7anBB9An362khehCxqydYNS5Igl0rtcP7dKC3ZBn1m2B9ULsyx46iNpfHQHHv9NKU2vVq2CtNc95CFktwjUwlyWMgbfI/DzPX/cC6KnglqsuVVBO7+jIaBmi0XGqudooZkqgIrvnfNMM13Gy78TUNHsCiAQEwZ/L17yNbzotNGxAoPfuXldbD52MQNOsA7WhH+j8qFWY6gZzTN4NpVtuW4m04TCEFexnTz\"]}";
    private static final String AWS_PUBLIC_KEY = "{\"kty\":\"RSA\",\"alg\":\"RS512\",\"use\":\"sig\",\"kid\":\"ap-northeast-11\",\"n\":\"AI7mc1assO5n6yB4b7jPCFgVLYPSnwt4qp2BhJVAmlXRntRZ5w4910oKNZDOr4fe/BWOI2Z7upUTE/ICXdqirEkjiPbBN/duVy5YcHsQ5+GrxQ/UbytNVN/NsFhdG8W31lsE4dnrGds5cSshLaohyU/aChgaIMbmtU0NSWQ+jwrW8q1PTvnThVQbpte59a0dAwLeOCfrx6kVvs0Y7fX7NXBbFxe8yL+JR3SMJvxBFuYC+/om5EIRIlRexjWpNu7gJnaFFwbxCBNwFHahcg5gdtSkCHJy8Gj78rsgrkEbgoHk29pk8jUzo/O/GuSDGw8qXb6w0R1+UsXPYACOXM8C8+E=\",\"e\":\"AQAB\"}";

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu5dwq8xsJHull0Pyevwk\n" +
            "3HCrXVM34xINFAYZaRICL9U7ZvkZy3S+SYe9TtTBlJ6iccpgIV3IEKm7cgyP5dMo\n" +
            "2ikVeVlXbkHUFIruTk/kfyLckLZUCh1HVfKeYv0zNXUI1nZpvm+h0ByaWoYTlZAH\n" +
            "s6L9402r+fUt4Pj4KC1Ke2sicx8gC1c1+QCFlJRm/PnXfhFnu/o+LiXrSbpD8rTc\n" +
            "LUlbzCXY+Azwj5MnnZH5Ksn6lUOMPI7cJ2iLnH0aEreLPMAR5/XTG4nLRM2lAzpH\n" +
            "LD7hvXPRUdWh9esUF99bPG2VFXJNxcjLrAb0YLU2rg3oL8AChhmwUnO3NfFUdU+H\n" +
            "bQXuqMaNpPaDkarPCOx9NVzYiEO2DXgciGYlk2UzU81GyOVxtdnJF0lG8UEgRTU0\n" +
            "MCbA7TO3zAp78Xp6RTlaDtTe4zOHeWaNyk5nHiu+BTofmXN33pyJDlOuLvP+BTi+\n" +
            "IaVCd50lWMOcl+AfKqLb81EYCcxAc6DZdU+v7OM+8JH6jWC48GZc9DCYpap3CzHm\n" +
            "KMSOc8cOmdVgIPPgc78Y68NWrpnssn8JB28boGSJfu1AC5l792WTWJYK4PPYBnuh\n" +
            "f+ofv/gOGcDMKdtoISmpq9NNvVir1CbazJlW+nXwGeSkV02RnMAkACx0Qp2mpb8C\n" +
            "HSeX3Wnk7YawCz7MCklktXUCAwEAAQ==\n" +
            "-----END PUBLIC KEY-----\n";
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQC7l3CrzGwke6WX\n" +
            "Q/J6/CTccKtdUzfjEg0UBhlpEgIv1Ttm+RnLdL5Jh71O1MGUnqJxymAhXcgQqbty\n" +
            "DI/l0yjaKRV5WVduQdQUiu5OT+R/ItyQtlQKHUdV8p5i/TM1dQjWdmm+b6HQHJpa\n" +
            "hhOVkAezov3jTav59S3g+PgoLUp7ayJzHyALVzX5AIWUlGb8+dd+EWe7+j4uJetJ\n" +
            "ukPytNwtSVvMJdj4DPCPkyedkfkqyfqVQ4w8jtwnaIucfRoSt4s8wBHn9dMbictE\n" +
            "zaUDOkcsPuG9c9FR1aH16xQX31s8bZUVck3FyMusBvRgtTauDegvwAKGGbBSc7c1\n" +
            "8VR1T4dtBe6oxo2k9oORqs8I7H01XNiIQ7YNeByIZiWTZTNTzUbI5XG12ckXSUbx\n" +
            "QSBFNTQwJsDtM7fMCnvxenpFOVoO1N7jM4d5Zo3KTmceK74FOh+Zc3fenIkOU64u\n" +
            "8/4FOL4hpUJ3nSVYw5yX4B8qotvzURgJzEBzoNl1T6/s4z7wkfqNYLjwZlz0MJil\n" +
            "qncLMeYoxI5zxw6Z1WAg8+Bzvxjrw1aumeyyfwkHbxugZIl+7UALmXv3ZZNYlgrg\n" +
            "89gGe6F/6h+/+A4ZwMwp22ghKamr0029WKvUJtrMmVb6dfAZ5KRXTZGcwCQALHRC\n" +
            "naalvwIdJ5fdaeTthrALPswKSWS1dQIDAQABAoICAQC2SZ7PEsIzYYOzze8e203m\n" +
            "eAXNlkREfxH+Vz7x/vHpEUe79GvAbR1Lzn+CzvOdO9mWwZVQVxVGO+lOFi7uoZad\n" +
            "CDc5yDtRhN5VZ/vSVYgwkuvKI6LegT0Eo9KNVoYgeC2yWTbAOzH+TQ0g0hDN0Tvq\n" +
            "r4QPETcAmeOPLd/XCsvJyn2baK921bQ41uz3SI4bXZytgLRQ0gcCSQ6ugjXs7xrV\n" +
            "VufBJTYFNG2+1rw0PdjmX4cE7LKlVh1QniKsWlSvw3OmAO5lfVc691dy8HJdBJCM\n" +
            "yj4KHzVUVEgh8+F+oSjDO6kXQg+ZFln0PH3US8Nqt1DctbS+ItBYDuIFpRDxPerV\n" +
            "t9wbAMW9/T8m5zAFXrgvQ6djnQC/EIpPAUpeQn5RbZqWPdCpEGusZzSUdl96Vgra\n" +
            "IYFbpJKOuyORoeYbeWHZ0OwwD6DY6E3nju9q1DmviPZFDIpTx9Gi2rALI7YdpabJ\n" +
            "EETKV/TSyeuZwYnQ0M9EgCIub46yd14UeLCX7FdPdHRF8QCdhbddzogVRNEN1CJe\n" +
            "IJbiTWNSwIgIkIcQNkCXttEUTwzMNXRIvwQFE53l5LJtqXi5uVaxeKDF3muO9X2j\n" +
            "wZsRE8UNg4EBCfq7ilsolBVASBrTG7K4vZ2FZ40/rnxY+hUGIf4gKm0r+BEjSlTm\n" +
            "ZXBS/oejfmwiyQ5woKBnMQKCAQEA51Pld5bGn/0WyuZ82Y3l0ckUR9mg7jaJNaSh\n" +
            "F9SK6SG4pPekXZzHI5/T8dqe28WYum8ZKSnqAolM2N+Kot6pG3JHvTg5IH+AcueW\n" +
            "skvrOuTBIWZ5l6oyiS/Hm/uXzxJAzvGbQRu+OhBt1sEgHvmvE30/hzC2YxA5nhrk\n" +
            "4XCAGUv5IoDswg5x9BW+75cwZRflLPKtQuWw5ICrv3sSFpSfoH1uqb+ng/kFJ3St\n" +
            "fv7kU6Hpb/Qm+2Guym8ik5F5g/sLL44i4xCqFx9Dq8gUMRnE6gNS56C+mq3YTZ2w\n" +
            "5/BqhsI/8kB5go0+WspUq8wdM3XzZK8SKnW8JdCpmhMxS2lmswKCAQEAz5lieY4+\n" +
            "sJTWmSGYOA5Nxm5O73JAYSXRWUaIKKBjk0PvwPi/CqproZrY5WO3JW0tAh4ILc63\n" +
            "xIBpeCL/BhVw78O4sfn++Ho/AB10MlcvhEN0mdlO8xChLiiELNTOAKvVz32honPY\n" +
            "YjlK1X84L6jfuxPTUMNB65Hnllr/j8ZBeOh8xzBZrFvfZIqap545W6+4XW3fjP83\n" +
            "KvDBPeqg4IzcHQZS5TB0Z3vgb4KHU7SY4p3qOPDpieKCWvaVCgk8AOCcMM4oZgWE\n" +
            "2msA7h5hXgc/Xfiy5+v9Ytw75V6OJSJnTMpokF7y8SmZ/PXQh9JZ/1WecKsclPtx\n" +
            "/kJYYH4FvqxHNwKCAQBpWSXJfpraRZJZuPnmwd6F2YMo7Y2Crsdx7JWImrzgSwEh\n" +
            "772k/D8clC8bl6p8/9H8JZhZzMLLgOfEZJlobuqomzTckXxCto4yxhE1BaoM2hyy\n" +
            "L070qQf2vhGzkbKjFPb6x8Eit5W8L7s18CHGuYLn50RFNwP4vWzf+fN+T5Om8Zh2\n" +
            "BCzOe3Gd7UFVL49Umrs96w7Ixn32sjqFK3EjY3AG0NjS6XtKeN/GBjb0/PPSuovq\n" +
            "9k/Cb8wAWPhwJ/IlDvEbKSnuKqqreQuCcc3wRoIM6JKa9fOX0dAOGOB14GFDGbex\n" +
            "hXdQ4y4gfsBstLofs3mywqANQiz7M7npdxAd/dRNAoIBAAt4WRWIQ3R0NMsvLP7j\n" +
            "4240SA44zM/RTBjXqcw82GOZnFSYKc4IDnxWVueNs9/QgW0dhawqQMMNqUYnANow\n" +
            "MxY8RScoPesyreputi3V3V08cOPTOuZ5I76uJGdptpwY4m5dbaHRLsJ2kejr54nS\n" +
            "ldH7TXCn6St/20DWdEpYVOO+TK6gwEOiq9wdQGBEgLzNH62h1Xkv3Ld1p+eo4Ayo\n" +
            "G71KzSe2nqfdE1B18M4yK0RSH0/YF78zkao+94sfaX5O6rJToa3JXkbHJL0DVrPg\n" +
            "SKMDi7b+tfhRXMnWiJoKpZR7ln1rkZa7irOMTWJDwA84htGI0sJ0hh7bQZDLRbv8\n" +
            "Ps8CggEBAMjE19ZtwCgX5+q6Z1SiklcLhe4WbWaFRNG0ecg4npSGcAAnqgL7OW8G\n" +
            "51ois8DNZ4Xe9uc6DIiVw32TKtggoQf1Ml5khNcFLjhucIL3uNqHQHkqDugJLeXe\n" +
            "Wz68/h0F8BqJC5bvJnOBqx4cH+qTANww7o56dxr10ZreoA4ytZBxd/+OwMS3O4Oa\n" +
            "MRIsK51hG4O3V80Ja1CenBEZF7rehl1X/dLERUpWvtbV/XclIv3VjbKZC6WUSg5Q\n" +
            "sGO/6Okf9XvvZUybLX5Ea/YjuRuMSjztzMNvUJNUZEIXnryYxZSjfU4BHra9QXb1\n" +
            "Lak+TAW6IT0pdV+0WnfC4yizNXwjqdQ=\n" +
            "-----END PRIVATE KEY-----\n";
    private static final String CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFyzCCA7OgAwIBAgIUOXSdjdjzNY/CUhr1gmLYCzSBy00wDQYJKoZIhvcNAQEL\n" +
            "BQAwdTELMAkGA1UEBhMCRlIxDjAMBgNVBAgMBVBhcmlzMQ4wDAYDVQQHDAVQYXJp\n" +
            "czEMMAoGA1UECgwDRmluMQ0wCwYDVQQLDARmZmRjMQ0wCwYDVQQDDARmZmRjMRow\n" +
            "GAYJKoZIhvcNAQkBFgtqdS5mZmRjLmNvbTAeFw0yMDA0MDkwNTU3MTRaFw0yMjA0\n" +
            "MDkwNTU3MTRaMHUxCzAJBgNVBAYTAkZSMQ4wDAYDVQQIDAVQYXJpczEOMAwGA1UE\n" +
            "BwwFUGFyaXMxDDAKBgNVBAoMA0ZpbjENMAsGA1UECwwEZmZkYzENMAsGA1UEAwwE\n" +
            "ZmZkYzEaMBgGCSqGSIb3DQEJARYLanUuZmZkYy5jb20wggIiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4ICDwAwggIKAoICAQC7l3CrzGwke6WXQ/J6/CTccKtdUzfjEg0UBhlpEgIv\n" +
            "1Ttm+RnLdL5Jh71O1MGUnqJxymAhXcgQqbtyDI/l0yjaKRV5WVduQdQUiu5OT+R/\n" +
            "ItyQtlQKHUdV8p5i/TM1dQjWdmm+b6HQHJpahhOVkAezov3jTav59S3g+PgoLUp7\n" +
            "ayJzHyALVzX5AIWUlGb8+dd+EWe7+j4uJetJukPytNwtSVvMJdj4DPCPkyedkfkq\n" +
            "yfqVQ4w8jtwnaIucfRoSt4s8wBHn9dMbictEzaUDOkcsPuG9c9FR1aH16xQX31s8\n" +
            "bZUVck3FyMusBvRgtTauDegvwAKGGbBSc7c18VR1T4dtBe6oxo2k9oORqs8I7H01\n" +
            "XNiIQ7YNeByIZiWTZTNTzUbI5XG12ckXSUbxQSBFNTQwJsDtM7fMCnvxenpFOVoO\n" +
            "1N7jM4d5Zo3KTmceK74FOh+Zc3fenIkOU64u8/4FOL4hpUJ3nSVYw5yX4B8qotvz\n" +
            "URgJzEBzoNl1T6/s4z7wkfqNYLjwZlz0MJilqncLMeYoxI5zxw6Z1WAg8+Bzvxjr\n" +
            "w1aumeyyfwkHbxugZIl+7UALmXv3ZZNYlgrg89gGe6F/6h+/+A4ZwMwp22ghKamr\n" +
            "0029WKvUJtrMmVb6dfAZ5KRXTZGcwCQALHRCnaalvwIdJ5fdaeTthrALPswKSWS1\n" +
            "dQIDAQABo1MwUTAdBgNVHQ4EFgQUAAghzA0SvY1ezG1QLbWNJnJsp8cwHwYDVR0j\n" +
            "BBgwFoAUAAghzA0SvY1ezG1QLbWNJnJsp8cwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n" +
            "hkiG9w0BAQsFAAOCAgEAOM+gdLqdbEfcpIXRt2Y3anokXPsVlonLjYPZYk5jJ+Ke\n" +
            "YUx0n1j2b37AdG51jdEDtTXjfEzR0loQeU31XSPYeF/a08aqpBaPwvBvaUNBhycp\n" +
            "ndCwEZUycXrHLCamSWGsELebdmBzdG0dpLdBKF+MHzWWEFmN6Sy+2DAykYr82mlj\n" +
            "l9NyTbWKammn1NVGd1oYTLPgbj/ZSartldfYWHRx9ur5YHLopgzWaaoO+/LWCcEi\n" +
            "+eIONUHxCePFMu7D+U3qpvb4YLXGE0itMhLv+HO/zNtXNy4K1xH2qc1RXyB+TuRc\n" +
            "aTKelem6lFYdDKVoMcex0+OiyktvyzatL7s9OISTCIW2rHCFjGQlhNUp3ADTpzG0\n" +
            "Nl04TCM6Py34M7b2ZMIio+i0DuOqV0H1TTMqwiWW+VDzrBLmVnH3SV+M75f5nwrW\n" +
            "cqpHasvRF9Glyi/US2BIALeEps37Mpv6fPoHBwitJkQdlb16YMUEMvqm1uIJm4OU\n" +
            "3IYJzwqC/Bc7EkBj0wNiWNh8chHN8IM/oA05ysynMvCTNQHfwTEYw9WnE+mgACo1\n" +
            "Nt2lyfShlILXSD1zzWl+EOe+KmrWx/SFW3b5rVOO0gXiDjxb7q4yaomO7dPC6Un9\n" +
            "QugtdkinNbJjXYMqMAZP5bPkZ51K+2Q9Bo+fv2LgDmGo9G0iSmG20DFz0UNq6oo=\n" +
            "-----END CERTIFICATE-----\n";

    public static void main(String[] args) throws Exception {
        // read X.509 certificate and RSA private key from Java keystore
        final String fileName = "src/main/resources/keystore.jks";
        final char[] storePass = "foo-keystore-pwd".toCharArray();
        final String alias = "foo-domain";
        final String keyPass = "foo-key-pwd";
        final KeyStore store = KeyStore.getInstance("JKS");
        final InputStream input = new FileInputStream(fileName);
        store.load(input, storePass);
        final Certificate certificateFromStore = store.getCertificate(alias);
        final RSAPublicKey publicKeyFromCertificate = (RSAPublicKey) certificateFromStore.getPublicKey();
        final RSAPrivateKey privateKeyFromStore = (RSAPrivateKey) store.getKey(alias, keyPass.toCharArray());

        // convert X.509 certificate to JWK
        final JWK jwkFromCertificate = JWK.parse((X509Certificate) certificateFromStore);
        // build JWK from Java keystore
        final JWK jwkFromKeyStore = JWK.load(store, alias, keyPass.toCharArray());

        // build JWK from PEM public key
        final JWK jwkFromPEMPublicKey = JWK.parseFromPEMEncodedObjects(PUBLIC_KEY);
        // build JWK from PEM private key
        final JWK jwkFromPEMPrivateKey = JWK.parseFromPEMEncodedObjects(PRIVATE_KEY);
        // build JWK from PEM certificate
        final JWK jwkFromPEMCertificate = JWK.parseFromPEMEncodedObjects(CERTIFICATE);

        // build public/private key from JWK
        final RSAPublicKey rsaPublicKeyFromJWK = jwkFromCertificate.toRSAKey().toRSAPublicKey();
        final RSAPrivateKey rsaPrivateKeyFromJWK = jwkFromCertificate.toRSAKey().toRSAPrivateKey();
        // build public key from JWK in JSON format
        final RSAKey rsaPublicKeyFromJsonJWK = RSAKey.parse(AZURE_PUBLIC_KEY);
    }
}

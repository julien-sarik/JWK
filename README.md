# JWK
Convert java.security keys from/to JWK

## Generate the keystore with
if the `-sigalg` option is not specified the default algorithm for signature is SHA256withRSA
`keytool -genkey -alias foo-domain -keyalg RSA -keystore keystore.jks -keysize 2048`


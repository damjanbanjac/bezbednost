package Busep.certificates;


import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import Busep.ModelDTO.SubjectDTO;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class CertificateGenerator {

    public CertificateGenerator() {
    }




    public static X509Certificate generateInterAndEnd(
            SubjectDTO subjectDTO,
            SubjectDTO subjectDTO2,
            KeyPair keyPair,
            final String hashAlgorithm,

            final int days)
            throws OperatorCreationException, CertificateException, IOException {

        //System.out.println(subjectDTO.getName());
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, subjectDTO.getName() + subjectDTO.getSurname());
        nameBuilder.addRDN(BCStyle.SURNAME, subjectDTO.getSurname());
        nameBuilder.addRDN(BCStyle.GIVENNAME, subjectDTO.getName());
        nameBuilder.addRDN(BCStyle.O, subjectDTO.getOrganisation());
        nameBuilder.addRDN(BCStyle.OU, subjectDTO.getOrgUnit());
        nameBuilder.addRDN(BCStyle.E, subjectDTO.getEmail());
        //UID (USER ID) je ID korisnika
        nameBuilder.addRDN(BCStyle.UID, subjectDTO.getId().toString());



        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

        KeyStoreWriter ks=new KeyStoreWriter();

        char[] array = "tim14".toCharArray();
        KeyStoreReader kr = new KeyStoreReader();
        ks.loadKeyStore("endCertificate.jks",array);

        PrivateKey pk = kr.readPrivateKey("endCertificate.jks","tim14",subjectDTO2.getId().toString(),subjectDTO2.getId().toString());
        System.out.println(subjectDTO2.getId());
        System.out.println(pk);
        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(pk);



        KeyUsage keyUse = new KeyUsage(KeyUsage.keyCertSign);
        X509Certificate certRoot = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", subjectDTO2.getId().toString());
        System.out.println(certRoot);
        final X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder( certRoot,
                        BigInteger.valueOf(now.toEpochMilli()),
                        notBefore,
                        notAfter,
                        nameBuilder.build(),
                        keyPair.getPublic())
                        .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                        .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .addExtension(Extension.keyUsage, true, keyUse);



        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
    }




    public static X509Certificate generateInter(
                                            SubjectDTO subjectDTO,
                                            KeyPair keyPair,
                                           final String hashAlgorithm,

                                           final int days)
            throws OperatorCreationException, CertificateException, IOException {

        System.out.println(subjectDTO.getName());
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, subjectDTO.getName() + subjectDTO.getSurname());
        nameBuilder.addRDN(BCStyle.SURNAME, subjectDTO.getSurname());
        nameBuilder.addRDN(BCStyle.GIVENNAME, subjectDTO.getName());
        nameBuilder.addRDN(BCStyle.O, subjectDTO.getOrganisation());
        nameBuilder.addRDN(BCStyle.OU, subjectDTO.getOrgUnit());
        nameBuilder.addRDN(BCStyle.E, subjectDTO.getEmail());
        //UID (USER ID) je ID korisnika
        nameBuilder.addRDN(BCStyle.UID, subjectDTO.getId().toString());



        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

        KeyStoreWriter ks=new KeyStoreWriter();

        char[] array = "tim14".toCharArray();
        KeyStoreReader kr = new KeyStoreReader();
        ks.loadKeyStore("rootCertificate.jks",array);
        PrivateKey pk = kr.readPrivateKey("rootCertificate.jks","tim14","root","tim14");
        System.out.println(pk);
        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(pk);



        KeyUsage keyUse = new KeyUsage(KeyUsage.keyCertSign);
       X509Certificate certRoot = (X509Certificate) kr.readCertificate("rootCertificate.jks", "tim14", "root");

        final X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder( certRoot,
                        BigInteger.valueOf(now.toEpochMilli()),
                        notBefore,
                        notAfter,
                        nameBuilder.build(),
                        keyPair.getPublic())
                        .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                        .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .addExtension(Extension.keyUsage, true, keyUse);



        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
    }


    public static X509Certificate generate(final KeyPair keyPair,
                                           final String hashAlgorithm,
                                           final String cn,
                                           final int days)
            throws OperatorCreationException, CertificateException, IOException {
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
        final X500Name x500Name = new X500Name("CN=" + cn);
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN,  cn);
        builder.addRDN(BCStyle.UID, "123456"); // da li hesovati id  ida li to se genericki dobija


        KeyUsage keyUse = new KeyUsage(KeyUsage.keyCertSign);

        final X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(builder.build(),
                        BigInteger.valueOf(now.toEpochMilli()),
                        notBefore,
                        notAfter,
                        builder.build(),
                        keyPair.getPublic())
                        .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                        .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .addExtension(Extension.keyUsage, true, keyUse);



        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
    }


    private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc =
                new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
            throws OperatorCreationException
    {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc =
                new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

}

package Busep.certificates;


import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;

import Busep.ModelDTO.ExtensionDTO;
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

            final int days,
            ExtensionDTO extensionDTO)
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
        ks.loadKeyStore("interCertificate.jks",array);

        PrivateKey pk = kr.readPrivateKey("interCertificate.jks","tim14",subjectDTO2.getId().toString(),subjectDTO2.getId().toString());

        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(pk);

        Boolean isCa = subjectDTO.isCA();

        boolean dig = false;
        boolean non = false;
        boolean agr =false;
        boolean enc = false;

        dig =   extensionDTO.getDigitalSignature() == true ? true : false;
        non =   extensionDTO.getNonRepudiation() == true ? true : false;
        agr =   extensionDTO.getKeyAgreement() == true ? true : false;
        enc =   extensionDTO.getKeyEncipherment() == true ? true : false;

        KeyUsage keyUse = new KeyUsage(KeyUsage.keyCertSign |
                (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyCertSign )
                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyCertSign  )
                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyCertSign )
                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyCertSign ));



        if(isCa == true) {



            X509Certificate certRoot = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim14", subjectDTO2.getId().toString());
            System.out.println(certRoot);
            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder( certRoot,
                            BigInteger.valueOf(now.toEpochMilli()),
                            notBefore,
                            notAfter,
                            nameBuilder.build(),
                            keyPair.getPublic())
                            .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                            .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(certRoot.getPublicKey()))
                            .addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa))
                            .addExtension(Extension.keyUsage, true, keyUse);



            return new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        } else {

            X509Certificate certRoot = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim14", subjectDTO2.getId().toString());
            System.out.println(certRoot);
            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder(certRoot,
                            BigInteger.valueOf(now.toEpochMilli()),
                            notBefore,
                            notAfter,
                            nameBuilder.build(),
                            keyPair.getPublic())
                            .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                            .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(certRoot.getPublicKey()))
                            .addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));

        if    (dig == true) {

                KeyUsage  keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.digitalSignature )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.digitalSignature  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.digitalSignature )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);

            } else if(non == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.nonRepudiation )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.nonRepudiation  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.nonRepudiation )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.nonRepudiation ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }
            else if(agr == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyAgreement )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyAgreement  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyAgreement )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyAgreement ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }
            else if( enc == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyEncipherment  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyEncipherment )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyEncipherment ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }





            return new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));

        }


    }




    public static X509Certificate generateInter(
            SubjectDTO subjectDTO,
            KeyPair keyPair,
            final String hashAlgorithm,

            final int days,
            ExtensionDTO extensionDTO)
            throws OperatorCreationException, CertificateException, IOException, ParseException {

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

        boolean dig = false;
        boolean non = false;
        boolean agr =false;
        boolean enc = false;

      dig =   extensionDTO.getDigitalSignature() == true ? true : false;
      non =   extensionDTO.getNonRepudiation() == true ? true : false;
      agr =   extensionDTO.getKeyAgreement() == true ? true : false;
      enc =   extensionDTO.getKeyEncipherment() == true ? true : false;

        KeyUsage keyUse = new KeyUsage(KeyUsage.keyCertSign |
                (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyCertSign )
                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyCertSign  )
                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyCertSign )
                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyCertSign ));








       X509Certificate certRoot = (X509Certificate) kr.readCertificate("rootCertificate.jks", "tim14", "root");

       Date certRDate = certRoot.getNotAfter();

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        if(certRDate.compareTo(notAfter) > 0) {
            System.out.println("veci je");
        }

        Boolean isCa = subjectDTO.isCA();

        if(isCa == true) {
            System.out.println("usao");
            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder( certRoot,
                            BigInteger.valueOf(now.toEpochMilli()),
                            notBefore,
                            notAfter,
                            nameBuilder.build(),
                            keyPair.getPublic())
                            .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                            .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(certRoot.getPublicKey()))
                            .addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa))
                            .addExtension(Extension.keyUsage, true, keyUse);




            return new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        }
        else {

            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder(certRoot,
                            BigInteger.valueOf(now.toEpochMilli()),
                            notBefore,
                            notAfter,
                            nameBuilder.build(),
                            keyPair.getPublic())
                            .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                            .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(certRoot.getPublicKey()))
                            .addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));




            if(dig == true) {

                KeyUsage  keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.digitalSignature )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.digitalSignature  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.digitalSignature )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.digitalSignature ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);

            } else if(non == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.nonRepudiation )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.nonRepudiation  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.nonRepudiation )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.nonRepudiation ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }
            else if(agr == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyAgreement )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyAgreement  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyAgreement )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyAgreement ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }
            else if( enc == true) {
                KeyUsage keyUseEnd = new KeyUsage(
                        (extensionDTO.getDigitalSignature() == true ? KeyUsage.digitalSignature : KeyUsage.keyEncipherment )
                                | (extensionDTO.getNonRepudiation() == true ? KeyUsage.nonRepudiation : KeyUsage.keyEncipherment  )
                                | (extensionDTO.getKeyAgreement() == true ? KeyUsage.keyAgreement : KeyUsage.keyEncipherment )
                                | (extensionDTO.getKeyEncipherment() == true ? KeyUsage.keyEncipherment : KeyUsage.keyEncipherment ));
                certificateBuilder.addExtension(Extension.keyUsage, true, keyUseEnd);
            }





            return new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        }
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

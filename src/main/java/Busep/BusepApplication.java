package Busep;

import Busep.ModelDTO.SubjectDTO;
import Busep.certificates.CertificateGenerator;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.DriverManager;

@SpringBootApplication
public class BusepApplication {

	public static void main(String[] args) throws CertificateException, IOException, OperatorCreationException, KeyStoreException {
		SpringApplication.run(BusepApplication.class, args);
		KeyStore ksf = null;
		KeyStoreWriter ks=new KeyStoreWriter();
		char[] array = "tim14".toCharArray();

		//ks.loadKeyStore("rootCer.jks",array);
		//ks.saveKeyStore("rootCer.jks",array);
		//KeyPair rootCertKeyPar = ks.generateKeyPair();
		CertificateGenerator certificate = new CertificateGenerator();
		//X509Certificate cert = certificate.generate(rootCertKeyPar, "SHA256WithRSAEncryption", "RootCert", 7300);
		//ks.write("root", rootCertKeyPar.getPrivate(), array, cert);
		// ks.saveKeyStore("rootCer.jks", array);
		//X509Certificate[] chain = new X509Certificate[2];
		//chain[0] = cert;
		//chain[1] = cert;
		//System.out.println(cert);
		////ksf.setKeyEntry("root", rootCertKeyPar.getPrivate(), array, chain);
		//ks.loadKeyStore("rootCer.jks",array);

		//KeyPair rootCertKeyPar = ks.generateKeyPair();

	//	CertificateGenerator certificate = new CertificateGenerator();
		//SubjectDTO subjectDTO = new SubjectDTO();
		KeyStoreReader kr=new KeyStoreReader();
		Certificate certRoot = kr.readCertificate("rootCertificate.jks", "tim14", "root");
		//X509Certificate cert = certificate.generateIntermidiateCertificate(subjectDTO, certRoot,5500);
		ks.loadKeyStore("endCertificate.jks",array);
		//char[] rootpass = "root".toCharArray();
		KeyPair keyPair = ks.generateKeyPair();
		SubjectDTO subject2 = new SubjectDTO();
		subject2.setId((long) 5);
		SubjectDTO subject = new SubjectDTO(1,"siman@gmail.com","simeunovic","bojan","ftn","odsek");
		subject.setId((long) 9);
		subject.setName("bojan");
		subject.setEmail("imejl");
		subject.setSurname("simeunovic");
		subject.setOrganisation("ftn");
		subject.setOrgUnit("e2");
		Certificate certIn = certificate.generateInterAndEnd(subject,subject2,keyPair ,"SHA256WithRSAEncryption",1300);
		ks.write(subject.getId().toString(), keyPair.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
		ks.saveKeyStore("endCertificate.jks", array);

		Certificate certRooti = kr.readCertificate("endCertificate.jks", "tim14", subject.getId().toString()); // kako izlastati sve sertifikate
		System.out.println(certRooti);

		// String c = certRoot.toString();
		System.out.println(certRooti);

	}




}

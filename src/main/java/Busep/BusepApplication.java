package Busep;

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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.DriverManager;

@SpringBootApplication
public class BusepApplication {

	public static void main(String[] args) throws CertificateException, IOException, OperatorCreationException {
		SpringApplication.run(BusepApplication.class, args);

		KeyStoreWriter ks=new KeyStoreWriter();
		char[] array = "tim14".toCharArray();


		ks.loadKeyStore("rootCertificate.jks",array);
		//ks.saveKeyStore("endCertificate.jks", array);
		KeyPair rootCertKeyPar = ks.generateKeyPair();

		CertificateGenerator certificate = new CertificateGenerator();
		Certificate cert = certificate.generate(rootCertKeyPar, "SHA256WithRSAEncryption", "RootCert", 7300);

		char[] rootpass = "root".toCharArray();
		ks.write("root", rootCertKeyPar.getPrivate(), rootpass, cert);

		KeyStoreReader kr=new KeyStoreReader();
		kr.readCertificate("rootCertificate.jks", "tim14", "root");
		System.out.println(cert);

	}




}

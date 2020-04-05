package Busep;

import keyStore.KeyStoreWriter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class BusepApplication {

	public static void main(String[] args) {
		SpringApplication.run(BusepApplication.class, args);

		KeyStoreWriter ks=new KeyStoreWriter();
		char[] array = "tim14".toCharArray();

		ks.loadKeyStore("endCertificate.jks",array);
		//ks.saveKeyStore("endCertificate.jks", array);
	}




}

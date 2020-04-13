package Busep.controller;


import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.ExtensionDTO;
import Busep.ModelDTO.SubjectDTO;
import Busep.Repository.SubjectRepository;
import Busep.Services.AdminServices;
import Busep.Services.SubjectService;
import Busep.certificates.CertificateGenerator;
import Busep.model.Admin;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import java.lang.reflect.Field;

import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import java.io.*;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLOutput;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@RestController

@RequestMapping(value = "/admin")
public class AdminController {

    @Autowired
    AdminServices adminServices;

    @Autowired
    SubjectService subjectService;

    @Autowired
    SubjectRepository subjectRepository;

    @GetMapping(value = "/sviAdmini")
    public ResponseEntity<List<AdminDTO>> getPostojeceAdmine() {


        List<Admin> admini = adminServices.findAll();

        List<AdminDTO> adminDTOList = new ArrayList<>();
        for (Admin admin : admini) {

            adminDTOList.add(new AdminDTO(admin));

        }

        return new ResponseEntity<>(adminDTOList, HttpStatus.OK);
    }



    @PostMapping(value="/addCertificate/{check}/{dani}/{zahtevId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId,@RequestBody ExtensionDTO extension) throws CertificateException, OperatorCreationException, IOException, ParseException, NoSuchFieldException, IllegalAccessException {

        long num = Long.parseLong(zahtevId);
        int danii = Integer.parseInt(dani);
        Subject subject = subjectService.findOne((num));
        subject.setCert(true);

        System.out.println("extension" + extension);

        System.out.println("digital potpis" +extension.getDigitalSignature());


     /*   Field field = clazz.getField("DigitalSignature");
        Object fieldValue = field.get(extension);
        System.out.println("Digital signature" + fieldValue); */
        if(check.equals("true")){

           subject.setCA(true);
        }
        subjectRepository.save(subject);
        KeyStoreWriter ks=new KeyStoreWriter();
        KeyPair keyPar = ks.generateKeyPair();
        SubjectDTO subjectDTO= new SubjectDTO(subject);
        char[] array = "tim14".toCharArray();
        CertificateGenerator certgen= new CertificateGenerator();
        Certificate certIn =certgen.generateInter(subjectDTO, keyPar, "SHA256WithRSAEncryption",danii,extension);
        ks.loadKeyStore("endCertificate.jks",array);
        ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
        ks.saveKeyStore("endCertificate.jks", array);
        KeyStoreReader kr=new KeyStoreReader();

        X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", zahtevId);
        System.out.println(cert);
    };

    @PostMapping(value="/addCertificate/{check}/{dani}/{zahtevId}/{issuerId}",consumes = MediaType.APPLICATION_JSON_VALUE)
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId,@PathVariable String issuerId,@RequestBody ExtensionDTO extension) throws CertificateException, OperatorCreationException, IOException {

        long num = Long.parseLong(zahtevId);
        long isuerId = Long.parseLong(issuerId);
        int danii = Integer.parseInt(dani);
        Subject subject = subjectService.findOne((num));
        Subject issuer = subjectService.findOne(isuerId);
        subject.setCert(true);

        if(check.equals("true")){

            subject.setCA(true);
        }
        subjectRepository.save(subject);
        KeyStoreWriter ks=new KeyStoreWriter();
        KeyPair keyPar = ks.generateKeyPair();
        SubjectDTO subjectDTO= new SubjectDTO(subject);
        SubjectDTO issuerDTO= new SubjectDTO(issuer);
        char[] array = "tim14".toCharArray();
        CertificateGenerator certgen= new CertificateGenerator();
        Certificate certIn =certgen.generateInterAndEnd(subjectDTO, issuerDTO, keyPar, "SHA256WithRSAEncryption",danii,extension);
        ks.loadKeyStore("endCertificate.jks",array);
        ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
        ks.saveKeyStore("endCertificate.jks", array);
        KeyStoreReader kr=new KeyStoreReader();

        X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", zahtevId);
        System.out.println(cert);
    };

    @GetMapping(value = "/getDani/{check}")
    public ArrayList<?> dozvoljeniDani(@PathVariable String check){
        ArrayList<Integer> dozvoljeni= new ArrayList<Integer>();
        char[] array = "tim14".toCharArray();
        System.out.println("ovo je check" + check);
        KeyStoreWriter ks=new KeyStoreWriter();
        ks.loadKeyStore("rootCertificate.jks",array);
        KeyStoreReader kr=new KeyStoreReader();

        X509Certificate certRoot = (X509Certificate) kr.readCertificate("rootCertificate.jks", "tim14", "root");
        Instant now = Instant.now();
        Date pocetniDan = Date.from(now);
        System.out.println(pocetniDan + "pocetni dan");
        Date dan = certRoot.getNotAfter();
        System.out.println(dan + "krajnji dan");
        LocalDate localDate = dan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(localDate + "krajnji dan konvertovan");
        LocalDate pocetni = pocetniDan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(pocetni + "pocetni dan konvertovan");
        //Period period =  Period.between(pocetni, localDate);
        //System.out.println(period + "period izmedju pocetnog i krajnjeg dana");
        long daysBetween = ChronoUnit.DAYS.between(pocetni, localDate);
        //int diff = period.getDays();
        System.out.println(daysBetween + "ukupno dana izmedju pocetnog i krjanjeg datuma");

        int godine=(int)daysBetween/365;
        int maxYear = 0;
        if(check.equals("true")) {

            maxYear = 15;
        } else {
            maxYear = 10;
        }
        for(int i=1; i<=godine; i++){

            dozvoljeni.add(365*i);
            System.out.println(365*i);
            if( i == maxYear) {
                break;
            }
        }

        return dozvoljeni;
    };

    @GetMapping(value = "/getDaniIntermediate/{id}/{check}")
    public ArrayList<?> dozvoljeniDaniIntermediate(@PathVariable String id,@PathVariable String check){
        ArrayList<Integer> dozvoljeni= new ArrayList<Integer>();
        char[] array = "tim14".toCharArray();
        System.out.println(id+"ovo je nas id");

        KeyStoreWriter ks=new KeyStoreWriter();
        ks.loadKeyStore("endCertificate.jks",array);

        KeyStoreReader kr=new KeyStoreReader();

        X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", id);

        Instant now = Instant.now();
        Date pocetniDan = Date.from(now);
        System.out.println(pocetniDan + "pocetni dan");
        Date dan = cert.getNotAfter();
        System.out.println(dan + "krajnji dan");
        LocalDate localDate = dan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(localDate + "krajnji dan konvertovan");
        LocalDate pocetni = pocetniDan.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        System.out.println(pocetni + "pocetni dan konvertovan");
        //Period period =  Period.between(pocetni, localDate);
        //System.out.println(period + "period izmedju pocetnog i krajnjeg dana");
        long daysBetween = ChronoUnit.DAYS.between(pocetni, localDate);
        //int diff = period.getDays();
        System.out.println(daysBetween + "ukupno dana izmedju pocetnog i krjanjeg datuma");

        int maxYear = 0;
        if(check.equals("true")) {

            maxYear = 15;
        } else {
            maxYear = 10;
        }

        int godine=(int)daysBetween/365;
        for(int i=1; i<=godine; i++){
            dozvoljeni.add(365*i);
            System.out.println(365*i);
            if( i == maxYear) {
                break;
            }
        }

        return dozvoljeni;
    };

    @GetMapping(value = "/download/{id}/{name}/{ca}")
    public void downloadCertificate(@PathVariable String id, @PathVariable String name, @PathVariable Boolean ca) throws IOException, CertificateEncodingException {

        KeyStoreWriter ks=new KeyStoreWriter();
        char[] array = "tim14".toCharArray();
        KeyStoreReader kr = new KeyStoreReader();
        X509Certificate cert = null;

        if(ca==true){
            ks.loadKeyStore("endCertificate.jks",array);//ustvari treba intermediate da ucita
            cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", id);
        }else{
            ks.loadKeyStore("endCertificate.jks",array);
            cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", id);
        }

        FileWriter fileWriter = new FileWriter(id+"_"+name+"_Certificate.txt");
        PrintWriter printWriter = new PrintWriter(fileWriter);
        printWriter.print(cert.toString());
        printWriter.close();

    };

}

package Busep.controller;


import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.SubjectDTO;
import Busep.Repository.SubjectRepository;
import Busep.Services.AdminServices;
import Busep.Services.SubjectService;
import Busep.certificates.CertificateGenerator;
import Busep.model.Admin;
import Busep.model.Subject;
import keyStore.KeyStoreWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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



    @PostMapping(value="/addCertificate/{check}/{dani}/{zahtevId}")
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId) throws CertificateException, OperatorCreationException, IOException, ParseException {

        long num = Long.parseLong(zahtevId);
        int danii = Integer.parseInt(dani);
        Subject subject = subjectService.findOne((num));
        subject.setCert(true);

        if(check.equals("true")){

           subject.setCA(true);
        }
        subjectRepository.save(subject);
        KeyStoreWriter ks=new KeyStoreWriter();
        KeyPair keyPar = ks.generateKeyPair();
        SubjectDTO subjectDTO= new SubjectDTO(subject);
        char[] array = "tim14".toCharArray();
        CertificateGenerator certgen= new CertificateGenerator();
        Certificate certIn =certgen.generateInter(subjectDTO, keyPar, "SHA256WithRSAEncryption",danii);
        ks.loadKeyStore("endCertificate.jks",array);
        ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
        ks.saveKeyStore("endCertificate.jks", array);
        System.out.println(certIn);
    };

    @PostMapping(value="/addCertificate/{check}/{dani}/{zahtevId}/{issuerId}")
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId,@PathVariable String issuerId) throws CertificateException, OperatorCreationException, IOException {

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
        Certificate certIn =certgen.generateInterAndEnd(subjectDTO, issuerDTO, keyPar, "SHA256WithRSAEncryption",danii);
        ks.loadKeyStore("endCertificate.jks",array);
        ks.write(subject.getId().toString(), keyPar.getPrivate() ,  subject.getId().toString().toCharArray(), certIn);
        ks.saveKeyStore("endCertificate.jks", array);
        System.out.println(certIn);
    };
}

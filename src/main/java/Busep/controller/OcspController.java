package Busep.controller;


import Busep.ModelDTO.SubjectDTO;
import Busep.Repository.SubjectRepository;
import Busep.Services.AdminServices;
import Busep.Services.OCSPService;
import Busep.Services.SubjectService;
import Busep.certificates.CertificateGenerator;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

@RestController

@RequestMapping(value = "/ocsp")

public class OcspController {
    @Autowired
    AdminServices adminServices;

    @Autowired
    SubjectService subjectService;

    @Autowired
    SubjectRepository subjectRepository;

    @Autowired
    OCSPService ocspService;


    @PostMapping(value="/revokeOcsp/{id}")
    public void revokeCert(@PathVariable String id) throws CertificateException, OperatorCreationException, IOException, ParseException {

        long num = Long.parseLong(id);
        Subject subject = subjectService.findOne((num));
        KeyStoreWriter ks=new KeyStoreWriter();
        char[] array = "tim14".toCharArray();
        KeyStoreReader kr = new KeyStoreReader();

        if(subject.isCA()==true){
            ks.loadKeyStore("interCertificate.jks",array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim14", id);
            ocspService.revokeCertificate(cert);
        }else{
            ks.loadKeyStore("endCertificate.jks",array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", id);
            ocspService.revokeCertificate(cert);
        }



    };

    @GetMapping(value="/checkValidity/{id}")
    public Boolean checkValidity(@PathVariable String id) throws CertificateException, OperatorCreationException, IOException, ParseException {

        long num = Long.parseLong(id);
        Subject subject = subjectService.findOne((num));
        KeyStoreWriter ks=new KeyStoreWriter();
        char[] array = "tim14".toCharArray();
        KeyStoreReader kr = new KeyStoreReader();

        if(subject.isCA()==true){
            ks.loadKeyStore("interCertificate.jks",array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("interCertificate.jks", "tim14", id);
            Boolean validan = ocspService.checkValidityOfParents(cert);
            return validan;
        }else{
            ks.loadKeyStore("endCertificate.jks",array);
            X509Certificate cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", id);
            Boolean validan = ocspService.checkValidityOfParents(cert);
            return validan;
        }



    };

}

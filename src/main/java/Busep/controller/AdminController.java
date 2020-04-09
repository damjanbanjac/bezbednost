package Busep.controller;


import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.SubjectDTO;
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
import java.util.ArrayList;
import java.util.List;

@RestController

@RequestMapping(value = "/admin")
public class AdminController {

    @Autowired
    AdminServices adminServices;

    @Autowired
    SubjectService subjectService;

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
    public void createCertificate(@PathVariable String check, @PathVariable String dani, @PathVariable String zahtevId) throws CertificateException, OperatorCreationException, IOException {

        System.out.println(dani);
        long num = Long.parseLong(zahtevId);
        int danii = Integer.parseInt(dani);
        Subject subject = subjectService.findOne((num));

        KeyStoreWriter ks=new KeyStoreWriter();
        KeyPair keyPar = ks.generateKeyPair();
        SubjectDTO subjectDTO= new SubjectDTO(subject);

        CertificateGenerator certgen= new CertificateGenerator();
        Certificate certIn =certgen.generateInter(subjectDTO, keyPar, "SHA256WithRSAEncryption",danii);

        System.out.println(certIn);
    };
}

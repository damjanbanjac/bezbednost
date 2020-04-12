package Busep.controller;

import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.SubjectDTO;
import Busep.Services.OCSPService;
import Busep.Services.SubjectService;
import Busep.model.Admin;
import Busep.model.Subject;
import keyStore.KeyStoreReader;
import keyStore.KeyStoreWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/subject")
public class SubjectController {

    @Autowired
    SubjectService subjectService;

    @Autowired
    OCSPService ocspService;

    @PostMapping
    public void newSubject(@RequestBody SubjectDTO subjectDTO){
        subjectService.newSubject(subjectDTO);
    }

    @GetMapping(value = "/zahteviSubjekata")
    public ResponseEntity<List<SubjectDTO>> getAllSubjects() {
        List<Subject> subjects = subjectService.findAll();
        List<SubjectDTO> subjectDTOList = new ArrayList<>();
        for(Subject subject : subjects) {
            if(subject.isCert() == false) {
                subjectDTOList.add(new SubjectDTO(subject));
            }
        }

        return new ResponseEntity<>(subjectDTOList, HttpStatus.OK);
    }

    @GetMapping(value = "/sviSertifikati")
    public ResponseEntity<List<SubjectDTO>> getAllCertficates() {
        List<Subject> subjects = subjectService.findAll();
        List<SubjectDTO> subjectDTOList = new ArrayList<>();
        for(Subject subject : subjects) {
            if(subject.isCert() == true) {
                subjectDTOList.add(new SubjectDTO(subject));
            }
        }

        return new ResponseEntity<>(subjectDTOList, HttpStatus.OK);
    }

    @GetMapping(value = "/CAsubjekti")
    public ResponseEntity<List<SubjectDTO>> getAllSubjectsCA() throws CertificateEncodingException {
        List<Subject> subjects = subjectService.findAll();
        List<SubjectDTO> subjectDTOList = new ArrayList<>();
        X509Certificate cert = null;
        KeyStoreWriter ks=new KeyStoreWriter();
        char[] array = "tim14".toCharArray();
        ks.loadKeyStore("endCertificate.jks",array);
        KeyStoreReader kr = new KeyStoreReader();

        for(Subject subject : subjects) {
            if(subject.isCert() == true && subject.isCA() == true) {
                cert = (X509Certificate) kr.readCertificate("endCertificate.jks", "tim14", subject.getId().toString());
                if(ocspService.checkValidityOfParents(cert) == true) {
                    subjectDTOList.add(new SubjectDTO(subject));
                }
            }
        }

        return new ResponseEntity<>(subjectDTOList, HttpStatus.OK);
    }


}

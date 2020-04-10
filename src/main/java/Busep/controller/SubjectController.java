package Busep.controller;

import Busep.ModelDTO.AdminDTO;
import Busep.ModelDTO.SubjectDTO;
import Busep.Services.SubjectService;
import Busep.model.Admin;
import Busep.model.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/subject")
public class SubjectController {

    @Autowired
    SubjectService subjectService;

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

    @GetMapping(value = "/CAsubjekti")
    public ResponseEntity<List<SubjectDTO>> getAllSubjectsCA() {
        List<Subject> subjects = subjectService.findAll();
        List<SubjectDTO> subjectDTOList = new ArrayList<>();
        for(Subject subject : subjects) {
            if(subject.isCert() == true && subject.isCA() == true) {
                subjectDTOList.add(new SubjectDTO(subject));
            }
        }

        return new ResponseEntity<>(subjectDTOList, HttpStatus.OK);
    }


}

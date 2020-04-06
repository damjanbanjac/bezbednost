package Busep.controller;

import Busep.ModelDTO.SubjectDTO;
import Busep.Services.SubjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/subject")
public class SubjectController {

    @Autowired
    SubjectService subjectService;

    @PostMapping
    public void newSubject(@RequestBody SubjectDTO subjectDTO){
        subjectService.newSubject(subjectDTO);
    }
}

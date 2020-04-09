package Busep.Services;

import Busep.ModelDTO.SubjectDTO;
import Busep.Repository.SubjectRepository;
import Busep.model.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SubjectService {

    @Autowired
    SubjectRepository subjectRepository;

    public void newSubject(SubjectDTO request){
        Subject subject = new Subject();
        subject.setDate(request.getDate());
        subject.setEmail(request.getEmail());
        subject.setName(request.getName());
        subject.setSurname(request.getSurname());
        subject.setOrganisation(request.getOrganisation());
        subject.setOrgUnit(request.getOrgUnit());
        subject.setCA(false);
        subject.setCert(false);
        subjectRepository.save(subject);
    }

    public List<Subject> findAll() {
        return subjectRepository.findAll();
    }

    public Subject findOne(Long id) {
        return subjectRepository.findById(id).orElseGet(null);
    }

}

package Busep.ModelDTO;

import Busep.model.Subject;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SubjectDTO {

    private Long id;

    private String email;

    private String surname;

    private String name;

    private String organisation;

    private String orgUnit;

    @JsonFormat(pattern = "dd/MM/yy")
    private Date date;

    private boolean isCA;

    private boolean cert;

    public SubjectDTO(int id, String mejl, String surname, String name, String organisation, String orgUnit, boolean isCA, boolean cert) {
    }

    public SubjectDTO(Subject subject) {
        this.id = subject.getId();
        this.email = subject.getEmail();
        this.surname = subject.getSurname();
        this.name = subject.getName();
        this.organisation = subject.getOrganisation();
        this.orgUnit = subject.getOrgUnit();
        this.date = subject.getDate();
        this.isCA = subject.isCA();
        this.cert = subject.isCert();
    }

}

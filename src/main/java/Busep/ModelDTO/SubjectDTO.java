package Busep.ModelDTO;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.util.Date;

@Data
public class SubjectDTO {

    private Long id;

    private String email;

    private String surname;

    private String name;

    private String organisation;

    private String orgUnit;

    @JsonFormat(pattern = "dd/MM/yy")
    private Date date;

    public SubjectDTO(int id, String mejl, String surname, String name, String organisation, String orgUnit) {
    }
}

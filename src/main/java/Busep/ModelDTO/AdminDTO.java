package Busep.ModelDTO;

import Busep.model.Admin;


public class AdminDTO {

    private long id;
    private String meil;

    public AdminDTO() {

    }

    public AdminDTO(long id, String meil) {
        this.id = id;
        this.meil = meil;
    }

    public AdminDTO(Admin admin) {
        this.id = admin.getId();

    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getMeil() {
        return meil;
    }

    public void setMeil(String meil) {
        this.meil = meil;
    }
}

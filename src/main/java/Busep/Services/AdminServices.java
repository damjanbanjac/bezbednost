package Busep.Services;


import Busep.Repository.AdminRepository;
import Busep.model.Admin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AdminServices {

    @Autowired
    AdminRepository adminRepository;

    public List<Admin> findAll() {
        return adminRepository.findAll();
    }


}

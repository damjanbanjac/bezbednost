package Busep.controller;


import Busep.ModelDTO.AdminDTO;
import Busep.Services.AdminServices;
import Busep.model.Admin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController

@RequestMapping(value = "/admin")
public class AdminController {

    @Autowired
    AdminServices adminServices;

    @GetMapping(value = "/sviAdmini")
    public ResponseEntity<List<AdminDTO>> getPostojeceAdmine() {


        List<Admin> admini = adminServices.findAll();

        List<AdminDTO> adminDTOList = new ArrayList<>();
        for (Admin admin : admini) {

            adminDTOList.add(new AdminDTO(admin));

        }

        return new ResponseEntity<>(adminDTOList, HttpStatus.OK);
    }
}

package br.com.diasnogueira.service.arquivo;

import br.com.diasnogueira.entities.Arquivo;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

public interface IArquivoService {

    Arquivo findByPath(String path);
    Optional<Arquivo> findById(Long id);
    Arquivo saveEnvioDocumento(MultipartFile arquivo);
    Arquivo saveModelo(MultipartFile arquivo);
    List<Arquivo> saveProcesso(List<MultipartFile> arquivo);
    void deleteById(Long id);
    List<Arquivo> findAllModelo();
    boolean validExtension(String extension);
}

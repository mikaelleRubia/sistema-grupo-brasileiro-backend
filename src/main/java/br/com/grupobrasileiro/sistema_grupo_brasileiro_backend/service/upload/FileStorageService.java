package br.com.grupobrasileiro.sistema_grupo_brasileiro_backend.service.upload;

import br.com.grupobrasileiro.sistema_grupo_brasileiro_backend.infra.exception.FileStorageException;
import br.com.grupobrasileiro.sistema_grupo_brasileiro_backend.infra.exception.MyFileNotFoundException;
import br.com.grupobrasileiro.sistema_grupo_brasileiro_backend.infra.exception.SShClientException;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import net.schmizz.sshj.xfer.InMemorySourceFile;
import net.schmizz.sshj.sftp.RemoteFile;
import net.schmizz.sshj.sftp.SFTPClient;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;
import java.nio.file.Files;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;

@Service
public class FileStorageService {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileStorageService.class);

    // Configurações do servidor EC2 remoto
    @Value("${sftpHost}")
    private String sftpHost;
    
    @Value("${sftpPort}")
    private int sftpPort;
    
    @Value("${sftpUser}")
    private String sftpUser; 
    
    @Value("${sftpPrivateKey}")
    private String sftpPrivateKey;

    @Value("${sftpRemoteDir}")
    private String sftpRemoteDir;

    public String storeFile(MultipartFile file) {
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        LOGGER.info("Iniciando armazenamento do arquivo: {}", fileName);

        try {
            if (fileName.contains("..")) {
                throw new FileStorageException("O nome do arquivo contém uma sequência de caminho inválida: " + fileName);
            }

            if (uploadToSFTP(file.getInputStream(), fileName)) {
                LOGGER.info("Upload do arquivo {} concluído com sucesso.", fileName);
                return fileName;
            }
            LOGGER.warn("Upload do arquivo {} falhou.", fileName);
            return null;
        } catch (Exception e) {
            LOGGER.error("Erro ao armazenar o arquivo {}: {}", fileName, e.getMessage(), e);
            throw new FileStorageException("Erro ao armazenar o arquivo " + fileName);
        }
    }

    private SSHClient connectToSFTPServer() throws IOException {
        SSHClient sshClient = new SSHClient();
        sshClient.addHostKeyVerifier(new PromiscuousVerifier());
        LOGGER.info("Conectando ao servidor SFTP em {}:{}", sftpHost, sftpPort);
        
        sshClient.connect(sftpHost, sftpPort);
        String privateKeyPath = sftpPrivateKey;
        LOGGER.info("Usando chave privada localizada em: {}", privateKeyPath);

        sshClient.authPublickey(sftpUser, privateKeyPath);
        LOGGER.info("Autenticação bem-sucedida para o usuário: {}", sftpUser);
        return sshClient;
    }

    private boolean uploadToSFTP(InputStream fileInputStream, String remoteFileName) {
        try (SSHClient sshClient = connectToSFTPServer()) {
            try (SFTPClient sftpClient = sshClient.newSFTPClient()) {
                LOGGER.info("Iniciando upload do arquivo para o servidor SFTP: {}", remoteFileName);
                
                sftpClient.put(new InMemorySourceFile() {
                    @Override
                    public String getName() {
                        return remoteFileName;
                    }
                    @Override
                    public long getLength() {
                        try {
                            return fileInputStream.available();
                        } catch (IOException e) {
                            LOGGER.error("Erro ao obter o tamanho do arquivo: {}", e.getMessage(), e);
                            return 0;
                        }
                    }
                    @Override
                    public InputStream getInputStream() {
                        return fileInputStream;
                    }
                }, sftpRemoteDir + "/" + remoteFileName);

                LOGGER.info("Arquivo {} enviado com sucesso para {}", remoteFileName, sftpRemoteDir);
                return true;
            }
        } catch (IOException e) {
            LOGGER.error("Erro ao conectar ou fazer upload para o servidor SFTP: {}", e.getMessage(), e);
            throw new SShClientException("Erro ao conectar ou fazer upload para o servidor SFTP: " + e.getMessage());
        }
    }

    public Pair<ByteArrayResource, String> loadFileAsResource(String fileName) {
        LOGGER.info("Carregando o arquivo {} do servidor SFTP.", fileName);
        
        try (SSHClient sshClient = connectToSFTPServer()) {
            try (SFTPClient sftpClient = sshClient.newSFTPClient();
                RemoteFile remoteFile = sftpClient.open(sftpRemoteDir + "/" + fileName);
                InputStream inputStream = remoteFile.new RemoteFileInputStream(0)) {

                byte[] fileContent = inputStream.readAllBytes();
                String mimeType = Files.probeContentType(Paths.get(fileName));

                LOGGER.info("Arquivo {} carregado com sucesso. MimeType: {}", fileName, mimeType);
                return Pair.of(new ByteArrayResource(fileContent), mimeType != null ? mimeType : "application/octet-stream");
            }
        } catch (IOException e) {
            LOGGER.error("Erro ao carregar o arquivo {}: {}", fileName, e.getMessage(), e);
            throw new MyFileNotFoundException("Erro ao carregar o arquivo: " + fileName);
        }
    }
}

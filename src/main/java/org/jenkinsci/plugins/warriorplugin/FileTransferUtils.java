package org.jenkinsci.plugins.warriorplugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class FileTransferUtils{

    /**
     * Uploads a file via SFTP
     * 
     * @param ipAddr Name or IP address
     * @param username Username
     * @param password Password
     * @param destDir Destination directory
     * @param uploadFile File to be uploaded
     * @throws JSchException JSchException
     * @throws SftpException SftpException
     * @throws IOException IOException
     */
    public static void sftpJSchUpload(String ipAddr, String username, String password, String destDir,
            File uploadFile) throws JSchException, SftpException, IOException {
        JSch jsch = new JSch();
        Session session = null;
        String saveFile = uploadFile.getName();
        session = jsch.getSession(username, ipAddr, 22);
        session.setConfig("StrictHostKeyChecking", "no");
        session.setPassword(password);
        session.connect();

        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;
        if (destDir != null && !(destDir.isEmpty())){
            saveFile = destDir + File.separator + saveFile;
        }
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(uploadFile);
            sftpChannel.put(fis, saveFile);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        sftpChannel.exit();
        session.disconnect();
    }

    /**
     * Downloads a file via SFTP
     * 
     * @param ipAddr Name or IP address
     * @param username Username
     * @param password Password
     * @param downloadFile File to be downloaded
     * @param saveFile Local name of the file to be downloaded
     * @throws JSchException JSchException
     * @throws SftpException SftpException
     * @throws IOException IOException
     */
    public static void sftpJSchDownload(String ipAddr, String username, String password,
            String downloadFile, File saveFile) throws JSchException, SftpException, IOException {
        JSch jsch = new JSch();
        Session session = null;
        session = jsch.getSession(username, ipAddr, 22);
        session.setConfig("StrictHostKeyChecking", "no");
        session.setPassword(password);
        session.connect();

        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp sftpChannel = (ChannelSftp) channel;

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(saveFile);
            sftpChannel.get(downloadFile, fos);
        } finally {
            if (fos != null) {
                fos.close();
            }
        }
        sftpChannel.exit();
        session.disconnect();
    }

    /**
     * Uploads a file via FTP
     * 
     * @param ipAddr Name or IP address
     * @param username Username
     * @param password Password
     * @param destDir Destination directory
     * @param uploadFile File to be downloaded
     * @throws IOException IOException
     */
    public static void ftpOpenConnUpload(String ipAddr, String username, String password,
            String destDir, File uploadFile) throws IOException {
        final int BUFFER_SIZE = 4096;
        String ftpUrl = "ftp://%s:%s@%s/%s;type=i";
        String saveFile = uploadFile.getName();
        if (destDir != null && !(destDir.isEmpty())){
            saveFile = destDir + File.separator + saveFile;
        }
        ftpUrl = String.format(ftpUrl, username, password, ipAddr, saveFile);
        URL url = new URL(ftpUrl);
        URLConnection conn = url.openConnection();
        OutputStream outputStream = conn.getOutputStream();
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(uploadFile);
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead = -1;
            while ((bytesRead = fis.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        outputStream.close();
    }

    /**
     * Upload a file via SCP
     * 
     * @param ipAddr Name or IP address
     * @param username Username
     * @param password Password
     * @param destDir Destination directory
     * @param uploadFile File to be downloaded
     * @throws JSchException JSchException
     * @throws IOException IOException
     * @throws InterruptedException InterruptedException
     */
    public static void scpJschUpload(String ipAddr, String username, String password, String destDir,
            File uploadFile) throws JSchException, IOException, InterruptedException{
        FileInputStream fis = null;
        String uploadFileName = uploadFile.getAbsolutePath();
        String saveFile = uploadFile.getName();
        if (destDir != null && !(destDir.isEmpty())){
            saveFile = destDir + File.separator + saveFile;
        }

        JSch jsch=new JSch();
        Session session = jsch.getSession(username, ipAddr, 22);
        session.setConfig("StrictHostKeyChecking", "no");
        session.setPassword(password);
        session.connect();

        boolean ptimestamp = true;

        //exec 'scp -t saveFile' remotely
        String command = "scp " + (ptimestamp ? "-p" :"") + " -t " + saveFile;
        Channel channel = session.openChannel("exec");
        ((ChannelExec)channel).setCommand(command);

        // get I/O streams for remote scp
        OutputStream out = channel.getOutputStream();
        InputStream in = channel.getInputStream();

        channel.connect();

        checkAck(in);

        if(ptimestamp){
            command = "T " + (uploadFile.lastModified()/1000) + " 0";
            // The access time should be sent here,
            // but it is not accessible with JavaAPI ;-<
            command += (" " + (uploadFile.lastModified()/1000) + " 0\n");
            out.write(command.getBytes(StandardCharsets.UTF_8));
            out.flush();
            checkAck(in);
        }

        // send "C0644 filesize filename", where filename should not include '/'
        long filesize = uploadFile.length();
        command = "C0644 " + filesize + " ";
        if(uploadFileName.lastIndexOf('/') > 0){
            command += uploadFileName.substring(uploadFileName.lastIndexOf('/') + 1);
        }
        else{
            command += uploadFileName;
        }
        command += "\n";
        out.write(command.getBytes());
        out.flush();
        checkAck(in);

        // send a content of file
        try {
            fis = new FileInputStream(uploadFile);
            byte[] buf = new byte[1024];
            while(true){
                int len = fis.read(buf, 0, buf.length);
                if(len <= 0)
                    break;
                out.write(buf, 0, len); //out.flush();
            }
            // send '\0'
            buf[0] = 0;
            out.write(buf, 0, 1);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        out.flush();
        checkAck(in);
        out.close();

        channel.disconnect();
        session.disconnect();
    }

    /**
     * Checks acknowledgement from InputStream
     * 
     * @param in Channel InputStream
     * @throws IOException IOException
     * @throws InterruptedException InterruptedException
     */
    static void checkAck(InputStream in) throws IOException, InterruptedException{
        int b = in.read();
        // b may be 0 for success,
        //          1 for error,
        //          2 for fatal error,
        //          -1
        if(b == 0 || b == -1)
            return;

        if(b == 1 || b == 2){
            StringBuffer sb = new StringBuffer();
            int c;
            do {
                c = in.read();
                sb.append((char)c);
            }
            while(c != '\n');
            throw new InterruptedException("SCP operation failed : " + sb.toString());
        }
    }

}
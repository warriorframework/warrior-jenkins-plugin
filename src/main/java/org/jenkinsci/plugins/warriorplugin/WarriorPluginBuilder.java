package org.jenkinsci.plugins.warriorplugin;

import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

import org.kohsuke.stapler.QueryParameter;
import org.apache.commons.lang.StringUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.transport.TransportHttp;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.jgit.transport.JschConfigSessionFactory;
import org.eclipse.jgit.transport.OpenSshConfig;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import org.jenkinsci.plugins.warriorplugin.FileTransferUtils;
import org.jenkinsci.remoting.RoleChecker;

public class WarriorPluginBuilder extends Builder implements SimpleBuildStep {

    private final String configType;
    private final String gitConfigUrl;
    private final boolean gitConfigCredentials;
    private final String gitConfigCloneType;
    private final String gitConfigTagValue;
    private final String gitConfigUname;
    private final String gitConfigPwd;
    private final String gitConfigFile;
    private final String sftpConfigIp;
    private final String sftpConfigUname;
    private final String sftpConfigPwd;
    private final String sftpConfigFile;
    private final String pythonPath;
    private final boolean uploadExecLog;
    private final String uploadServerIp;
    private final String uploadServerUname;
    private final String uploadServerPwd;
    private final String uploadServerType;
    private final String uploadServerDir;
    private final List<WarriorRunFileParam> runFiles;

    /**
     * Create Warrior Framework build action
     * 
     * Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
     * 
     * @param configType Type of configuration file source(GIT repository or SFTP sever)
     * @param gitConfigUrl URL of GIT repository
     * @param gitConfigCredentials Option to provide GIT user credentials
     * @param gitConfigTagValue Value of Branch/Commit ID/Tag
     * @param gitConfigCloneType Clone type(Branch/Commit ID/Tag)
     * @param gitConfigUname Username for GIT
     * @param gitConfigPwd Password for GIT
     * @param gitConfigFile Path of configuration file(GIT)
     * @param sftpConfigIp Name or IP address of SFTP server
     * @param sftpConfigUname Username of SFTP server
     * @param sftpConfigPwd Password of SFTP server
     * @param sftpConfigFile Path of configuration file(SFTP)
     * @param pythonPath Absolute path of python executable
     * @param uploadExecLog Option to upload execution log
     * @param uploadServerIp Name or IP address of log-upload-server
     * @param uploadServerUname Username of log-upload-server
     * @param uploadServerPwd Password of log-upload-server
     * @param uploadServerType Type of log-upload-server(FTP/SFTP/SCP)
     * @param uploadServerDir Destination directory of log-upload-server
     * @param runFiles Warrior files to be executed
     */

    @DataBoundConstructor
    public WarriorPluginBuilder(String configType, String gitConfigUrl, boolean gitConfigCredentials, String gitConfigTagValue,
            String gitConfigCloneType, String gitConfigUname, String gitConfigPwd, String gitConfigFile, String sftpConfigIp,
            String sftpConfigUname, String sftpConfigPwd, String sftpConfigFile,String pythonPath,
            boolean uploadExecLog, String uploadServerIp, String uploadServerUname, String uploadServerPwd,
            String uploadServerType, String uploadServerDir, List<WarriorRunFileParam> runFiles) {
        this.configType = configType;
        this.gitConfigUrl = gitConfigUrl;
        this.gitConfigCredentials = gitConfigCredentials;
        this.gitConfigCloneType = gitConfigCloneType;
        this.gitConfigTagValue = gitConfigTagValue;
        this.gitConfigUname = gitConfigUname;
        this.gitConfigPwd =  gitConfigPwd;
        this.gitConfigFile = gitConfigFile;
        this.sftpConfigIp = sftpConfigIp;
        this.sftpConfigUname = sftpConfigUname;
        this.sftpConfigPwd = sftpConfigPwd;
        this.sftpConfigFile = sftpConfigFile;
        this.pythonPath = pythonPath;
        this.uploadExecLog = uploadExecLog;
        this.uploadServerIp = uploadServerIp;
        this.uploadServerUname = uploadServerUname;
        this.uploadServerPwd = uploadServerPwd;
        this.uploadServerType = uploadServerType;
        this.uploadServerDir = uploadServerDir;
        this.runFiles = runFiles;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     * @return
     *      Each value provided in the configuration UI.
     */
    public String getConfigType() {
        return configType;
    }

    public String getGitConfigUrl() {
        return gitConfigUrl;
    }

    public boolean isGitConfigCredentials() {
        return gitConfigCredentials;
    }

    public String getGitConfigCloneType() {
        return gitConfigCloneType;
    }

    public String getGitConfigTagValue() {
        return gitConfigTagValue;
    }
    public String getGitConfigUname() {
        return gitConfigUname;
    }

    public String getGitConfigPwd() {
        return gitConfigPwd;
    }

    public String getGitConfigFile() {
        return gitConfigFile;
    }

    public String getSftpConfigIp() {
        return sftpConfigIp;
    }

    public String getSftpConfigUname() {
        return sftpConfigUname;
    }

    public String getSftpConfigPwd() {
        return sftpConfigPwd;
    }

    public String getSftpConfigFile() {
        return sftpConfigFile;
    }

    public String getPythonPath() {
        return pythonPath;
    }

    public String getUploadServerIp() {
        return uploadServerIp;
    }

    public boolean isUploadExecLog() {
        return uploadExecLog;
    }

    public String getUploadServerUname() {
        return uploadServerUname;
    }

    public String getUploadServerPwd() {
        return uploadServerPwd;
    }

    public String getUploadServerType() {
        return uploadServerType;
    }

    public String getUploadServerDir() {
        return uploadServerDir;
    }

    public List<WarriorRunFileParam> getRunFiles() {
        return runFiles;
    }

    // act(FileCallable) to support remoting - to execute the code based on the FilePath
    // ShellCallable - to execute shell commands in FilePath location(master/slave)
    private static class ShellCallable implements FileCallable<Boolean> {
        private static final long serialVersionUID = 1L;
        private final TaskListener listener;
        private String shellOutput = null;
        private final String[] command;
        private final String[] envp;
        private boolean status = true;
        public ShellCallable(String[] command, String[] envp, TaskListener listener){
            this.command = command;
            this.envp = envp;
            this.listener = listener;
            }
        @Override
        public Boolean invoke(File file, VirtualChannel channel){
            try{
                Process pShell = Runtime.getRuntime().exec(command, envp, file);
                BufferedReader stdInput = new BufferedReader(new 
                        InputStreamReader(pShell.getInputStream(), StandardCharsets.UTF_8));
                BufferedReader stdError = new BufferedReader(new 
                        InputStreamReader(pShell.getErrorStream(), StandardCharsets.UTF_8));
                try {
                    // read the output from Shell execution
                    listener.getLogger().println("Execution log:");
                    while ((shellOutput = stdInput.readLine()) != null) {
                        listener.getLogger().println(shellOutput);
                    }
                    // read any errors from Shell execution
                    listener.getLogger().println("Error log(if any):");
                    while ((shellOutput = stdError.readLine()) != null) {
                        listener.getLogger().println(shellOutput);
                    }
                    // Return false for non-zero exit code
                    if (pShell.waitFor() != 0){
                        listener.getLogger().println("Execution failed with exit code: " + pShell.waitFor());
                        return false;
                    }
                } finally {
                    stdInput.close();
                    stdError.close();
                }
            }catch(IOException | InterruptedException e){
                status = false;
                e.printStackTrace(listener.getLogger());
            }
            return status;
        }
        @Override
        public void checkRoles(RoleChecker arg0) throws SecurityException {}
    }

    // GitCallable - to Clone GIT repositories in FilePath location(master/slave)
    private static class GitCallable implements FileCallable<Boolean> {
        private static final long serialVersionUID = 1L;
        private final TaskListener listener;
        private final String username;
        private final String password;
        private final String url;
        private final File localDir;
        private String branch;
        private String cloneType;

        private boolean status = true;
        public GitCallable(WarriorPluginBuilder obj, File localDir, TaskListener listener){
            this.username = obj.gitConfigUname;
            this.password = obj.gitConfigPwd;
            this.url = obj.gitConfigUrl;
            this.localDir = localDir;
            this.branch = obj.gitConfigTagValue;
            this.cloneType = obj.gitConfigCloneType;
            this.listener = listener;
            }

        public GitCallable(String username, String password, String url, File localDir,
                           String branch, String cloneType, TaskListener listener){
            this.username = username;
            this.password = password;
            this.url = url;
            this.localDir = localDir;
            this.branch = branch;
            this.cloneType = cloneType;
            this.listener = listener;
            }

        @Override
        public Boolean invoke(File file, VirtualChannel channel){
            try{
                Git git = Git.cloneRepository()
                        .setURI(url)
                        .setDirectory(localDir)
                        .setTransportConfigCallback(getTransportConfigCallback())
                        .setCredentialsProvider(new UsernamePasswordCredentialsProvider(username, password))
                        .call();

                // Default branch to checkout is master
                if(branch==null || branch.isEmpty()){
                    branch = "master";
                } else if (cloneType.equals("branch")){
                    branch = "origin" + File.separator + branch;
                }
                git.checkout().setName(branch).call();
                git.close();
                }catch(GitAPIException e){
                    status = false;
                    e.printStackTrace(listener.getLogger());
                }
            return status;
        }
        @Override
        public void checkRoles(RoleChecker arg0) throws SecurityException {}

        public static TransportConfigCallback getTransportConfigCallback() {
            final SshSessionFactory sshSessionFactory = new JschConfigSessionFactory() {
                @Override
                protected void configure(OpenSshConfig.Host host, Session session) {
                    //session.setPassword(password);
                }
            };
            return new TransportConfigCallback() {

                public void configure(Transport transport) {
                    if (transport instanceof TransportHttp)
                        return;
                    SshTransport sshTransport = (SshTransport) transport;
                    sshTransport.setSshSessionFactory(sshSessionFactory);
                }
            };
        }
    }

    // FileUploadCallable - to upload a file to remote server from FilePath location(master/slave)
    private static class FileUploadCallable implements FileCallable<Boolean> {
        private static final long serialVersionUID = 1L;
        private final TaskListener listener;
        private String uploadType;
        private String ipAddr;
        private String username;
        private String password;
        private String destDir;
        private File uploadFolder;
        private File uploadFile;
        private boolean status = true;
        public FileUploadCallable(WarriorPluginBuilder obj, File uploadFolder, File uploadFile, TaskListener listener){
            this.uploadType = obj.uploadServerType;
            this.ipAddr = obj.uploadServerIp;
            this.username = obj.uploadServerUname;
            this.password = obj.uploadServerPwd;
            this.destDir = obj.uploadServerDir;
            this.uploadFolder = uploadFolder;
            this.uploadFile = uploadFile;
            this.listener = listener;
        }
        @Override
        public Boolean invoke(File file, VirtualChannel channel) {
            try {
                FolderZipUtils.zipFolder(uploadFolder, uploadFile);
                if(uploadType.equals("ftp")){
                    FileTransferUtils.ftpOpenConnUpload(ipAddr, username, password, destDir, uploadFile);
                }else if(uploadType.equals("sftp")){
                    FileTransferUtils.sftpJSchUpload(ipAddr, username, password, destDir, uploadFile);
                }else if(uploadType.equals("scp")){
                    FileTransferUtils.scpJschUpload(ipAddr, username, password, destDir, uploadFile);
                }
            } catch (JSchException | SftpException | IOException | InterruptedException e){
                status = false;
                e.printStackTrace(listener.getLogger());
            }

        return status;
        }
        @Override
        public void checkRoles(RoleChecker arg0) throws SecurityException {}
    }

    // FileDownloadCallable - to download a file from SFTP server to FilePath location(master/slave)
    private static class FileDownloadCallable implements FileCallable<Boolean> {
        private static final long serialVersionUID = 1L;
        private final TaskListener listener;
        private String ipAddr;
        private String username;
        private String password;
        private String downloadFile;
        private File saveFile;
        private boolean status = true;
        public FileDownloadCallable(WarriorPluginBuilder obj, File saveFile, TaskListener listener){
            this.ipAddr = obj.sftpConfigIp;
            this.username = obj.sftpConfigUname;
            this.password = obj.sftpConfigPwd;
            this.downloadFile = obj.sftpConfigFile;
            this.saveFile = saveFile;
            this.listener = listener;
        }
        @Override
        public Boolean invoke(File file, VirtualChannel channel) {
            try {
                FileTransferUtils.sftpJSchDownload(ipAddr, username, password, downloadFile, saveFile);
            } catch (JSchException | SftpException | IOException e){
                status = false;
                e.printStackTrace(listener.getLogger());
            }

        return status;
        }
        @Override
        public void checkRoles(RoleChecker arg0) throws SecurityException {}
    }

    @Override
    public void perform(Run<?,?> build, FilePath workspace, Launcher launcher, TaskListener listener) {

        try {

            if (configType.equals("configGit")){
                // Clone the GIT repository which has Warhorn config file
                cloneConfigRepo(build, workspace, listener);
            } else if (configType.equals("sftpConfig")){
                // Copy warhorn configuration file from SFTP server to jenkins workspace
                copySftpWarhornConfig(build, workspace, listener);
            }

            // Clone WarriorFramework to Job Workspace
            cloneWarriorFramework(build, workspace, listener);

            // Run Warhorn with provided Warhorn config file to setup the environment
            runWarhorn(build, workspace, listener);

            // Execute Warrior File(s) - proj/ts/tc
            runWarrior(build, workspace, listener);

            // To copy Log files to remote server(ftp/sftp/scp)
            if(uploadExecLog == true){
                uploadWarriorLog(build, workspace, listener);
            }
        } catch (Exception e){
            e.printStackTrace(listener.getLogger());
            build.setResult(Result.FAILURE);
        }
    }

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link WarriorPluginBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/hudson/plugins/hello_world/HelloWorldBuilder/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */

        /**
         * In order to load the persisted global configuration, you have to 
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            load();
        }

        /**
         * Performs on-the-fly validation of the form field 'name'.
         *
         * @param value
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         *      <p>
         *      Note that returning {@link FormValidation#error(String)} does not
         *      prevent the form from being saved. It just means that a message
         *      will be displayed to the user. 
         * @throws IOException IOException
         * @throws ServletException ServletException
         */

        public FormValidation doCheckGitConfigUrl(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "URL for GIT repository");
        }

        public FormValidation doCheckGitConfigFile(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "Warhorn config file");
        }

        public FormValidation doCheckRunFile(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "File to run");
        }

        public FormValidation doCheckGitConfigUname(@QueryParameter String value, @QueryParameter boolean gitConfigCredentials)
                throws IOException, ServletException {
            if (gitConfigCredentials){
                return checkFieldNotEmpty(value, "Username");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckGitConfigPwd(@QueryParameter String value, @QueryParameter boolean gitConfigCredentials)
                throws IOException, ServletException {
            if (gitConfigCredentials){
                return checkFieldNotEmpty(value, "Password");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUploadServerIp(@QueryParameter String value, @QueryParameter boolean uploadExecLog)
                throws IOException, ServletException {
            if (uploadExecLog){
                return checkFieldNotEmpty(value, "Server name/IP");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUploadServerUname(@QueryParameter String value, @QueryParameter boolean uploadExecLog)
                throws IOException, ServletException {
            if (uploadExecLog){
                return checkFieldNotEmpty(value, "Username");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUploadServerPwd(@QueryParameter String value, @QueryParameter boolean uploadExecLog)
                throws IOException, ServletException {
            if (uploadExecLog){
                return checkFieldNotEmpty(value, "Password");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckSftpConfigIp(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "SFTP server name/IP");
        }

        public FormValidation doCheckSftpConfigUname(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "Username");
        }

        public FormValidation doCheckSftpConfigPwd(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "Password");
        }

        public FormValidation doCheckSftpConfigFile(@QueryParameter String value)
                throws IOException, ServletException {
            return checkFieldNotEmpty(value, "Configuration file");
        }

        private FormValidation checkFieldNotEmpty(String value, String field) {
            value = StringUtils.strip(value);
            if (value == null || value.equals("")) {
                return FormValidation.error(field + " is required.");
            }
            return FormValidation.ok();
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types 
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        public String getDisplayName() {
            return "Warrior Framework Plugin";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().

            // ^Can also use req.bindJSON(this, formData);
            save();
            return super.configure(req,formData);
        }

    }

    /**
     * Clones a GIT repo into configRepo directory in workspace
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException InterruptedException
     * @throws IOException IOException
     */
    public void cloneConfigRepo(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException {
        boolean status = true;
        listener.getLogger().println(">> Cloning warhornConfigRepo: " + gitConfigUrl + " to " +
         workspace.getRemote() + "/configRepo");
        // Repo will be cloned inside configRepo directory
        FilePath ws = new FilePath(workspace, "configRepo");
        if(ws.exists()){
            ws.deleteRecursive();
        }
        File localPath = new File(ws.toURI());
        // Perform clone operation in Workspace(Master/Slave)
        status = workspace.act(new GitCallable(this, localPath, listener));
        if (status != true) {
            throw new InterruptedException("Cloning warhornConfigRepo: " + gitConfigUrl + " failed");
        }
    }

    /**
     * Clones warriorframework into Jenkins workspace
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException InterruptedException
     * @throws IOException IOException
     * @throws SAXException SAXException
     * @throws ParserConfigurationException ParserConfigurationException
     */
    public void cloneWarriorFramework(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException, ParserConfigurationException, SAXException {
        boolean status = true;
        listener.getLogger().println(">> Cloning WarrioFramework: " + gitConfigUrl + " to " + workspace.getRemote());

        // Get required details to clone WarriorFramework
        String[] cloneDetails = getWfCloneDetails(build, workspace, listener);

        // warriorframework will be cloned inside '<worksapce>/WarriorFramework' directory
        FilePath ws = new FilePath(workspace, "WarriorFramework");
        if(ws.exists()){
            ws.deleteRecursive();
        }
        File localPath = new File(ws.toURI());
        // Setting cloneType as 'tag' to avoid adding 'origin' with branch name
        // 'origin' is required when using branches and it is mandatory in warhorn config file
        String cloneType = "tag";
        // Perform clone operation in Workspace(Master/Slave)
        status = workspace.act(new GitCallable(cloneDetails[0], cloneDetails[1],
                  cloneDetails[2], localPath, cloneDetails[3], cloneType, listener));
        if (status != true) {
            throw new InterruptedException("Cloning WarriorFramework: " + gitConfigUrl + " failed");
        }
        listener.getLogger().println(">> Successfuly cloned WarrioFramework");
    }

    /**
     * Private method to get the values given in warriorframework
     * tag of warhorn config file
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @return cloneDetails Details required to clone warriorframework
     * @throws ParserConfigurationException ParserConfigurationException
     * @throws SAXException SAXException
     * @throws IOException IOException
     */
    private String[] getWfCloneDetails(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws ParserConfigurationException, SAXException, IOException{

        String absWarhornConfig = "";
        String[] cloneDetails = new String[4];
        if (configType.equals("configGit")){
            absWarhornConfig = workspace.getRemote() + "/configRepo/" + gitConfigFile;
        } else {
            absWarhornConfig = workspace.getRemote() + "/warhorn_config.xml";
        }

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document document = db.parse(new File(absWarhornConfig));
        NodeList wfNodeList = document.getElementsByTagName("warriorframework");
        String url = "";
        String branch = "";
        if(wfNodeList.getLength() > 0){
            Element element = (Element) wfNodeList.item(0);
            url = element.getAttribute("url");
            branch = element.getAttribute("label");
        }
        if (url.isEmpty()){
            url = "https://github.com/warriorframework/warriorframework.git";
        }
        if (branch.isEmpty()){
            branch = "origin/develop";
        }

        // Temp_fix: Using the username & password given for cloning warhorn config file.
        // These will be empty/default if not provided for warhorn config file
        cloneDetails[0] = this.gitConfigUname;
        cloneDetails[1] = this.gitConfigPwd;
        cloneDetails[2] = url;
        cloneDetails[3] = branch;

        return cloneDetails;
    }

    /**
     * Private method to get the name of the virtual environment
     * given in virtualenv tag of warhorn config file
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @return virtEnvName Name of the Virtual Environment
     * @throws ParserConfigurationException ParserConfigurationException
     * @throws SAXException SAXException
     * @throws IOException IOException
     */
    private String getVirtEnvName(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws ParserConfigurationException, SAXException, IOException{

        String absWarhornConfig = "";
        if (configType.equals("configGit")){
            absWarhornConfig = workspace.getRemote() + "/configRepo/" + gitConfigFile;
        } else {
            absWarhornConfig = workspace.getRemote() + "/warhorn_config.xml";
        }
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document document = db.parse(new File(absWarhornConfig));
        NodeList veNodeList = document.getElementsByTagName("virtualenv");

        String virtEnvName = "";
        if(veNodeList.getLength() > 0){
            Element element = (Element) veNodeList.item(0);
            virtEnvName = element.getAttribute("name");
        }

        return virtEnvName;
    }


    /**
     * Executes warhorn with given config file to setup warrior execution environment
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException
     * @throws IOException IOException
     * @throws SAXException SAXException
     * @throws ParserConfigurationException ParserConfigurationException
     */
    private void runWarhorn(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException, ParserConfigurationException, SAXException {
        boolean status = true;
        String absWarhornConfig = "";
        listener.getLogger().println(">> Creating warrior execution environment");

        if (configType.equals("configGit")){
            absWarhornConfig = workspace.getRemote() + "/configRepo/" + gitConfigFile;
        } else {
            absWarhornConfig = workspace.getRemote() + "/warhorn_config.xml";
        }

        listener.getLogger().println("Absolute path of warhorn configuration file: "+ absWarhornConfig);
        String warhornCmd = "python " + workspace.getRemote() + "/WarriorFramework/warhorn/warhorn.py " + absWarhornConfig;
        listener.getLogger().println("warhornCmd is: "+ warhornCmd);

        String[] command = {
                "bash",
                "-c",
                warhornCmd
        };

        String [] envp = {};
        status = workspace.act(new ShellCallable(command, envp, listener));
        if (status != true) {
            throw new InterruptedException("Warrior execution environment creation failed");
        }
        listener.getLogger().println(">> Successfuly created warrior execution environment");
       }

    /**
     * Executes Warrior File(s) - proj/ts/tc
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException InterruptedException
     * @throws IOException IOException
     * @throws SAXException SAXException
     * @throws ParserConfigurationException ParserConfigurationException
     */
    private void runWarrior(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException, ParserConfigurationException, SAXException {
        boolean status = true;
        listener.getLogger().println(">> Warrior execution begins:");
        String warriorPath = workspace.getRemote() + "/WarriorFramework/warrior/";
        String warriorExe = warriorPath + "Warrior";

        Iterator<WarriorRunFileParam> warriorRunFileIter = runFiles.iterator();
        StringBuffer buf = new StringBuffer();
        while(warriorRunFileIter.hasNext()){
            WarriorRunFileParam runFileParam = warriorRunFileIter.next();
            String absRunFile = " " + warriorPath + "Warriorspace/" + runFileParam.getRunFile().trim();
            buf.append(absRunFile);
        }

        String runFileCommand = buf.toString();
        String executionDir = warriorPath + "Warriorspace/Execution";
        String warriorCmd = "python " + warriorExe + runFileCommand + " -outputdir " + executionDir;
        listener.getLogger().println("Warrior command: "+ warriorCmd);

        String virtEnvName = getVirtEnvName(build, workspace, listener);

        if (!virtEnvName.isEmpty()){
            String virtEnvLoc = workspace.getRemote() + File.separator + virtEnvName;
            String virtActCmd = "source " + virtEnvLoc + "/bin/activate && ";
            warriorCmd = virtActCmd + warriorCmd + " && deactivate";
        }

        String[] command = {
                "bash",
                "-c",
                warriorCmd
        };

        String [] envp = {};

        status = workspace.act(new ShellCallable(command, envp, listener));
        if (status != true) {
            listener.getLogger().println(">> Warrior execution failed");
            build.setResult(Result.FAILURE);
        }
        listener.getLogger().println(">> Successfully completed Warrior execution");
    }

    /**
     * Uploads Warrior Execution Logs to remote server
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException InterruptedException
     * @throws IOException IOException
     * @throws SAXException SAXException
     * @throws ParserConfigurationException ParserConfigurationException
     */
    private void uploadWarriorLog(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException, ParserConfigurationException, SAXException {
        boolean status = true;
        listener.getLogger().println(">> Uploading warrior execution logs");
        File execLogFolder = new File(workspace.getRemote(), "/WarriorFramework/warrior/Warriorspace/Execution");
        String buildTag = build.getEnvironment(listener).get("BUILD_TAG");
        File execLogZip = new File(workspace.getRemote(), "/WarriorFramework/warrior/Warriorspace/Execution_"+ buildTag + ".zip");
        status = workspace.act(new FileUploadCallable(this, execLogFolder, execLogZip, listener));
        if (status != true) {
            throw new InterruptedException("Uploading warrior execution logs failed");
        } else {
            listener.getLogger().println(">> Successfully uploaded Warrior Execution logs to : " + 
             uploadServerIp + ":" + uploadServerDir + "/Execution_"+ buildTag + ".zip");
            //(sftp)logger.println("Uploaded Warrior Execution logs to : " + uploadServerIp + "://" + uploadServerDir);
            //(ftp)logger.println("Uploaded Warrior Execution logs: " + uploadServerUname + "@" + uploadServerIp + "/" + uploadServerDir);
        }
    }

    /**
     * Copy warhorn configuration file from SFTP server to jenkins workspace
     *
     * @param build Build
     * @param workspace Jenkins job workspace
     * @param listener Task listener
     * @throws InterruptedException InterruptedException
     * @throws IOException IOException
     */
    private void copySftpWarhornConfig(Run<?,?> build, FilePath workspace, TaskListener listener)
            throws IOException, InterruptedException {
        boolean status = true;
        listener.getLogger().println(">> Copying warhorn config file to jenkins workspace as warhorn_config.xml");
        File saveFile = new File(workspace.getRemote(), "warhorn_config.xml");
        status = workspace.act(new FileDownloadCallable(this, saveFile, listener));
        if (status != true) {
            throw new InterruptedException("Copying warhorn config file failed");
        } else {
            listener.getLogger().println(">> Successfully copied warhorn config file to jenkins workspace");
        }
    }
}

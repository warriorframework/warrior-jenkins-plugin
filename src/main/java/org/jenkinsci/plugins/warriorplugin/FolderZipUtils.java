package org.jenkinsci.plugins.warriorplugin;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import org.apache.commons.io.IOUtils;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class FolderZipUtils {

    /**
     * Zips a folder
     * 
     * @param folder Folder to be zipped
     * @param zipFile Name of the zipped file
     * @throws IOException IOException
     */
    public static void zipFolder(final File folder, final File zipFile) throws IOException {
        zipFolder(folder, new FileOutputStream(zipFile));
    }

    /**
     * Zips a folder
     * 
     * @param folder Folder to be zipped
     * @param outputStream File OutputStream
     * @throws IOException IOException
     */
    public static void zipFolder(final File folder, final OutputStream outputStream) throws IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            processFolder(folder, zipOutputStream, folder.getPath().length() + 1);
        }
    }

    private static void processFolder(final File folder, final ZipOutputStream zipOutputStream, final int prefixLength)
            throws IOException {
        File[] folderListFiles = folder.listFiles();
        if (folderListFiles != null) {
            for (final File file : folderListFiles) {
                if (file.isFile()) {
                    final ZipEntry zipEntry = new ZipEntry(file.getPath().substring(prefixLength));
                    zipOutputStream.putNextEntry(zipEntry);
                    try (FileInputStream inputStream = new FileInputStream(file)) {
                        IOUtils.copy(inputStream, zipOutputStream);
                    }
                    zipOutputStream.closeEntry();
                } else if (file.isDirectory()) {
                    processFolder(file, zipOutputStream, prefixLength);
                }
            }
        }
    }
}
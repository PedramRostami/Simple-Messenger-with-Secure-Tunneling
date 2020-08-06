package libs;

import java.io.*;
import java.util.List;

public class FileManagement {
    public static String readFile(String path){
        try {
            File file = new File(path);
            if (!file.exists()) {
                System.out.println("wrong path");
                throw new FileNotFoundException();
            }
            BufferedReader br = new BufferedReader(new FileReader(file));
            String st;
            StringBuilder text = new StringBuilder();
            boolean firstLine = true;
            while ((st = br.readLine()) != null)
                if (firstLine) {
                    text.append(st);
                    firstLine = false;
                } else
                    text.append("\n").append(st);

            return text.toString();
        } catch (FileNotFoundException e) {
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean writeFile(String path, String text) {
        File file = new File(path);
        try {
            file.createNewFile();
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(text);
            fileWriter.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean makeDirectory(String dirName) {
        File file = new File(dirName);
        return file.mkdir();
    }

    public static File[] getDirectoryFiles(String dirName) {
        File file = new File(dirName);
        return file.listFiles();
    }

    public static boolean writeToFile(byte[] data, File file) {
        try {
            file.createNewFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}

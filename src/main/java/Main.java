import org.apache.commons.io.FileUtils;
import rc4.RC4;
import salsa20.Salsa20;

import java.io.File;
import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
        RC4 rc4 = new RC4();

        String keyRC4 = "This is my key to test1234";
        //String filePath = "src/main/resources/sample-large-text-file.txt"; //big file    //not included due to github rules
        String filePath ="src/main/resources/textToTest.txt"; //simple text

        long startTime, endTime, timeElapsed;
        File file = new File(filePath);
        byte[] inputBytes = FileUtils.readFileToByteArray(file);

        startTime = System.nanoTime();
        rc4.doEncryption(inputBytes, keyRC4);
        endTime = System.nanoTime();

        timeElapsed = endTime - startTime;


        System.out.println("Encryption is finished for RC4");
        System.out.println("Execution time in milliseconds : " +
                timeElapsed / 1000000.0);
        System.out.println("Execution time in seconds : " +
                timeElapsed / 1000000000.0);
        System.out.println();


        //Salsa20 encryption

        int symKeySize = 16;
        int symIVSize = 8;
        byte[] iv = new byte[symIVSize];
        byte[] keySalsa = new byte[symKeySize];
        Salsa20 eCipher = new Salsa20();

        eCipher.init(keySalsa, iv);

        startTime = System.nanoTime();
        eCipher.crypt(inputBytes, 0, inputBytes.length);
        endTime = System.nanoTime();
        timeElapsed = endTime - startTime;
        System.out.println("Encryption is finished for Salsa20");
        System.out.println("Execution time in milliseconds : " +
                timeElapsed / 1000000.0);
        System.out.println("Execution time in seconds : " +
                timeElapsed / 1000000000.0);
        System.out.println();

    }
}

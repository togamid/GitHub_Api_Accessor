import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;

public class Logger {

    private int errorCount = 0;

    private final boolean debugEnabled;

    private final String logPath;

    public Logger(String logPath) {
        this.logPath = logPath + "/log.txt";
        this.debugEnabled = false;
    }

    public Logger(String logPath, boolean debugEnabled) {
        this.logPath = logPath + "/log.txt";
        this.debugEnabled = debugEnabled;
    }

    public void log(Exception e, String message) {
        log(LogLevel.ERROR, message +": " + e.getMessage());
        log(LogLevel.DEBUG, e.toString());
        log(LogLevel.DEBUG, Arrays.toString(e.getStackTrace()));
    }

    public void log(LogLevel logLevel, String message) {
        if(!debugEnabled && logLevel == LogLevel.DEBUG) {
            return;
        }
        if(logLevel == LogLevel.ERROR) {
            errorCount++;
        }
        String logMessage = "[" + logLevel.toString() + "] " + message;
        System.out.println(logMessage);
        appendToFile(logPath, logMessage);
    }

    public void resetErrorCount() {
        errorCount = 0;
    }

    public int getErrorCount() {
        return errorCount;
    }

    private static void appendToFile(String path, String line) {
        BufferedWriter writer;
        try {
            writer = new BufferedWriter(new FileWriter(path, true));
            writer.write(line);
            writer.newLine();
            writer.close();
        } catch (IOException e) {
            System.out.println("ERROR: COULD NOT WRITE LOG TO FILE!");
        }
    }
}

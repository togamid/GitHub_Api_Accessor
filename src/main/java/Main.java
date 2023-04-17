import org.kohsuke.github.*;

import java.io.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Stream;

public class Main {
    private final static String baseIOPath = "./data";
    private static final Date[] relevantDates = new Date[]{
            createDate(2022, 12, 31),
            createDate(2022, 6, 30),
            createDate(2021, 12, 31),
            createDate(2021, 6, 30),
            createDate(2020, 12, 31),
            createDate(2020, 6, 30),
            createDate(2019, 12, 31),
            createDate(2019, 6, 30),
            createDate(2019, 1, 1)

    };
    private static final String token = "token";

    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static int numberOfUnsuccessfulAnalysis = 0;
    private static final Logger logger = new Logger(baseIOPath, true);
    private static final SQLiteConnector sqLiteConnector = new SQLiteConnector(logger);
    private static long currentRepoID = 0;
    public static void main(String[] args) throws IOException {
        GitHub github = GitHubBuilder.fromPropertyFile().build();
        sqLiteConnector.initConnection(baseIOPath, "completeData.db");
        sqLiteConnector.createTables();

        logger.log(LogLevel.INFO, "Begin loading repo list");
        String[] repoNames = loadRepoList(baseIOPath + "/repos.txt");
        setup();
        logger.log(LogLevel.INFO, "Begin analysing repos. Number of repos found: " + repoNames.length);
        for(String repoName: repoNames) {
            logger.resetErrorCount();
            logger.log(LogLevel.INFO, "Begin analysing repo " + repoName);
            currentRepoID = 0;
            try {
                GHRepository foreignRepo = github.getRepository(repoName);
                currentRepoID = foreignRepo.getId();
                sqLiteConnector.addRepository(foreignRepo);
                //clone and enable Vulnerability reports
                GHRepository repo = prepRepo(github, foreignRepo);
                GHCommit[] pomCommits = getPomCommitsAtDates(repo, relevantDates);
                cloneInitRepo(repo);
                //analyze current state
                analyze(repo, Calendar.getInstance().getTime());

                // analyze previous states
                for(GHCommit commit : pomCommits) {
                    try {
                        resetRepo(repo, commit);
                        analyze(repo, commit.getAuthoredDate());
                    }
                    catch (Exception e) {
                        logger.log(e,"Failed to process Commit " + commit.getSHA1() + " at " + commit.getCommitDate() + " for Repo " + repoName);
                    }
                }

                removeRepo(foreignRepo.getOwnerName(), repo, github);
            }
            catch (Exception e) {
                logger.log(e, "An error occurred while analysing repo " + repoName);
            }

            if(logger.getErrorCount() == 0) {
                try {
                    appendToFile(baseIOPath + "/successfulRepos.txt", repoName);
                }
                catch (Exception e) {
                    logger.log(LogLevel.WARN, "Could not add repo " + repoName + " to file of successfully finished repos.");
                }
            }
            else {
                numberOfUnsuccessfulAnalysis++;
            }
        }

        tearDown();

        if(numberOfUnsuccessfulAnalysis == 0) {
            logger.log(LogLevel.INFO, "Analysis completed successfully for all "+repoNames.length + " repos");
        }
        else {
            logger.log(LogLevel.WARN, "Analysis finished with errors. Errors in " + numberOfUnsuccessfulAnalysis + " out of " + repoNames.length +" repos");
        }

    }

    public static void setup() {
        try {
            executeScript("setup.sh");
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void removeRepo(String originalOwner, GHRepository repository, GitHub github) throws IOException {
        if(!originalOwner.equals(github.getMyself().getLogin())){
            repository.delete();
        }
    }

    public static void tearDown() {
        try {
            executeScript("clean_up.sh");
            sqLiteConnector.closeConnection();
            executor.shutdown();
        }
        catch (Exception e) {
            logger.log(e, "An error Occured while cleaning up");
        }
    }

    public static void cloneInitRepo(GHRepository repository) {
        try {
            executeScript("clone_init_repo.sh", repository.getOwnerName(), repository.getName());
        }
        catch (Exception e) {
            throw new RuntimeException("An error Occured while cloning and initialising repo: " + repository.getFullName() + ". Cause: " + e, e);
        }
    }

    public static void resetRepo(GHRepository repository, GHCommit commit) throws Exception {
            executeScript("reset_repo.sh", repository.getName(), commit.getSHA1());
    }

    public static void analyze(GHRepository repository, Date date) {
        int scanID = sqLiteConnector.addScan(date, currentRepoID);
        String folderName = repository.getOwnerName() + "_" + repository.getName();
        new File(baseIOPath+ "/" + folderName).mkdir();
        try {
            Vulnerability[] dependabotVulnerabilities = analyzeDependabot(repository);
            try {
                safeVulnerabilities(dependabotVulnerabilities, baseIOPath + "/" + folderName, date, "dependabot");
            }
            catch (Exception e) {
                logger.log(e, "Saving dependabot Vulns as CSV for repo " + repository.getFullName() +" and date " + date + " failed");
            }
            try {
                sqLiteConnector.addVulnerabilities(currentRepoID, date, dependabotVulnerabilities, VulnerabilityScanner.DEPENDABOT, scanID);
            }
            catch (Exception e) {
                logger.log(e, "Saving dependabot Vulns in SQLite for repo " + repository.getFullName() +" and date " + date + " failed");
            }
        }
        catch (Exception e) {
            logger.log(e, "Scan of dependabot Vulns for repo " + repository.getFullName() +" and date " + date + " failed");
        }

        try {
            Vulnerability[] owaspVulnerabilities = analyzeOwasp();
            System.out.println("Analyze OWASP returned");
            try {
                safeVulnerabilities(owaspVulnerabilities, baseIOPath + "/" + folderName, date, "owasp");
                System.out.println("ulnerabilities returned");
            }
            catch (Exception e) {
                logger.log(e, "Saving OWASP Vulns as CSV for repo " + repository.getFullName() +" and date " + date + " failed");
            }
            try {
                sqLiteConnector.addVulnerabilities(currentRepoID, date, owaspVulnerabilities, VulnerabilityScanner.OWASP, scanID);
                System.out.println("Swfe OWASP SQLIite eturned");
            }
            catch (Exception e) {
                logger.log(e, "Saving OWASP Vulns in SQLite for repo " + repository.getFullName() +" and date " + date + " failed");
            }
        }
        catch (Exception e) {
            logger.log(e, "Scan of OWASP Vulns for repo " + repository.getFullName() +" and date " + date + " failed");
        }

    }

    public static void safeVulnerabilities(Vulnerability[] vulnerabilities, String folderPath, Date date, String prefix) {
        String pattern = "yyyy_MM_dd";
        DateFormat df = new SimpleDateFormat(pattern);
        if(vulnerabilities == null || vulnerabilities.length != 0) {
            String path = folderPath + "/" + prefix + "_" + df.format(date) + ".txt";
            try {
                BufferedWriter writer = new BufferedWriter(new FileWriter(path));
                if(vulnerabilities != null) {
                    for (Vulnerability entry : vulnerabilities) {
                        writer.write(entry.toCsvLine());
                        writer.newLine();
                    }
                }
                else {
                    writer.write("ERROR");
                }
                writer.close();
            } catch (IOException e) {
                throw new RuntimeException("Could not safe vulnerability results in " + path + ". Cause: " + e.getMessage(), e);
            }
        }
    }

    public static Vulnerability[] analyzeDependabot(GHRepository repository) {
        GHDependabotAlert[] dependabotAlerts;
        try {
            dependabotAlerts = repository.getDependabotAlerts();
            dependabotAlerts = Stream.of(dependabotAlerts)
                    .filter(alert -> alert.getState() == GHDependabotAlert.State.OPEN)
                    .toArray(GHDependabotAlert[]::new);
        } catch (Exception e) {
            throw new RuntimeException("Could not load Dependabot Alerts for Repo " + repository.getFullName()+ ". Cause: " + e.getMessage(), e);
        }
        List<Vulnerability> dependabotVulnerabilities = new ArrayList<>();
        for(GHDependabotAlert alert : dependabotAlerts) {
            Vulnerability vulnerability = new Vulnerability();
            vulnerability.cveIdentifier = alert.getCveId();
            vulnerability.cvssScore = alert.getCvssScore();
            vulnerability.cweIds = alert.getCweIds();
            vulnerability.publishedAt = alert.getPublishedAt();
            vulnerability.scope = alert.getScope().toString();
            vulnerability.severity = alert.getSeverity().toString();
            dependabotVulnerabilities.add(vulnerability);
        }

        return dependabotVulnerabilities.toArray(new Vulnerability[0]);
    }

    public static Vulnerability[] analyzeOwasp() throws Exception {
        executeScript("analyze_owasp.sh");
        try {
            return OWASPConnector.loadOWASPVulns("tmp/dependency-check-report.xml");
        }
        catch (IOException e) {
            throw new RuntimeException("Could not load OWASP report. Cause: " + e.getMessage());
        }

    }

    public static void executeScript(String script, String... args) throws Exception {
        try {
            String[] command = new String[2 + args.length];
            System.arraycopy(args, 0, command, 2, args.length);
            command[0] = "sh";
            command[1] = "/root/app/scripts/" + script;
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.directory(new File(System.getProperty("user.home") + "/app"));
            builder.environment().put("GIT_USERNAME", "togamid");
            builder.environment().put("GIT_PASSWORD", token);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            StreamGobbler streamGobbler =
                    new StreamGobbler(process.getInputStream(), System.out::println);
            Future<?> future = executor.submit(streamGobbler);
            boolean terminated = process.waitFor(30, TimeUnit.MINUTES);
            if (!terminated) {
                process.destroyForcibly();
                logger.log(LogLevel.ERROR,"Something went wrong when executing " + script);
            }
            future.get(30, TimeUnit.SECONDS);
        }
        catch (Exception e) {
            throw new Exception("An error occured while executing script " + script + " with args " + Arrays.toString(args) +". Cause: " + e.getMessage(), e);
        }
    }

    public static GHCommit[] getPomCommitsAtDates(GHRepository repository, Date[] dates) throws IOException {
        if(dates.length == 0) {
            return new GHCommit[0];
        }
        Arrays.sort(dates, Collections.reverseOrder());
        PagedIterator<GHCommit> commitIterator = repository.queryCommits()
                .path("pom.xml")
                .until(dates[0])
                .list()._iterator(100);
        List<GHCommit> foundCommits = new ArrayList<>();
        Date currentSearchedDate;
        GHCommit currentCommit = commitIterator.next();
        while(commitIterator.hasNext() && foundCommits.size() < dates.length) {
            currentSearchedDate = dates[foundCommits.size()];
            // not before to include all commits which are on the same date or before
            if(!currentCommit.getCommitDate().after(currentSearchedDate)) {
                foundCommits.add(currentCommit);
            }
            else {
                currentCommit = commitIterator.next();
            }
        }
        if(foundCommits.size() != dates.length) {
            logger.log(LogLevel.WARN, "Only " + foundCommits.size() + " Commits found for repo " + repository.getFullName() +" out of maximum " + dates.length);
        }
        return foundCommits.stream().distinct().toArray(GHCommit[]::new);
    }

    private static void appendToFile(String path, String line) throws Exception {
        BufferedWriter writer;
        try {
            writer = new BufferedWriter(new FileWriter(path, true));
            writer.write(line);
            writer.newLine();
        } catch (IOException e) {
            throw new Exception(e);
        }
        try {
            writer.close();
        } catch (IOException e) {
            throw new Exception(e);
        }
    }

    public static GHRepository prepRepo(GitHub github, GHRepository oldRepo) throws IOException {
        GHRepository newRepo;

        if(oldRepo.getOwnerName().equals(github.getMyself().getLogin())) {
            newRepo = oldRepo;
        }
        else {
            newRepo = oldRepo.fork();
        }
        newRepo.enableVulnerabilityAlerts();
        return newRepo;
    }

    public static String[] loadRepoList(String path) throws IOException {
        String[][] rawLines = loadCsv(path, ";");
        return Stream.of(rawLines)
                .filter(line -> line.length != 0)
                .map(line -> line[0])
                .filter(name -> !name.isEmpty())
                .toArray(String[]::new);
    }

    private static String[][] loadCsv(String path, String separator) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String[][] lines = reader.lines().map(line -> line.split(separator)).toArray(String[][]::new);
        reader.close();
        return lines;
    }

    // filters ", " to " " to filter out commas in the free text
    private static String[][] loadOwaspCsv(String path, String separator) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String[][] lines = reader.lines().map(line -> line.replace(", ", " ")).map(line -> line.split(separator)).toArray(String[][]::new);
        reader.close();
        return lines;
    }

    public static Date createDate(int year, int month, int day) {
        return Date.from(LocalDate.of(year, month, day).atStartOfDay(ZoneId.of("Z")).toInstant());
    }
}

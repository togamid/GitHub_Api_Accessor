import org.kohsuke.github.GHRepository;

import java.io.IOException;
import java.sql.*;
import java.util.Date;
import java.text.SimpleDateFormat;

public class SQLiteConnector {

    private final Logger logger;
    private int vulnsWithoutCVE = 0;

    public SQLiteConnector(Logger logger) {
        this.logger = logger;
    }

    //hat repository_id, original_owner, name, evtl. creation_date, size,
    private static final String createRepositoryTable = "CREATE TABLE IF NOT EXISTS Repository (" +
            "repository_id INTEGER PRIMARY KEY," +
            "original_owner TEXT NOT NULL," +
            "name TEXT NOT NULL," +
            "creation_date TEXT," +
            "size INTEGER" +
            ");";

    //hat cve_id, cvss3_score, severity, published_at, Cwe_IDs (comma separated), scope
    private static final String createVulnerabilityTable = "CREATE TABLE IF NOT EXISTS Vulnerability (" +
            "cve_id TEXT PRIMARY KEY," +
            "cvss3_score REAL," +
            "severity TEXT," +
            "published_at TEXT," +
            "cwe_ids TEXT," +
            "scope TEXT" +
            ");";
    // hat scan_id , scan_date, repository_id
    private static final String createScanTable ="CREATE TABLE IF NOT EXISTS Scan (" +
            "scan_id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "scan_date TEXT NOT NULL," +
            "repository_id INTEGER," +
            "FOREIGN KEY (repository_id) REFERENCES Repository (repository_id) ON DELETE CASCADE"+
            ");";

    //hat cve_id, repository_id, date (ISO8601 / YYYY-MM-DD HH:MM:SS.SSS), found_by, cpe_confidence (wenn OWASP), evidence_Count (wenn OWASP)
    private static final String createOccurrenceTable = "CREATE TABLE IF NOT EXISTS Occurrence (" +
            "cve_id TEXT NOT NULL," +
            "repository_id INTEGER NOT NULL," +
            "date TEXT NOT NULL," +
            "found_by TEXT NOT NULL," +
            "cpe_confidence TEXT," +
            "evidence_count INTEGER, " +
            "scan_id INTEGER, " +
            "PRIMARY KEY (cve_id, repository_id, date, found_by)," +
            "FOREIGN KEY (cve_id) REFERENCES Vulnerability (cve_id) ON DELETE CASCADE," +
            "FOREIGN KEY (repository_id) REFERENCES Repository (repository_id) ON DELETE CASCADE," +
            "FOREIGN KEY (scan_id) REFERENCES Scan (scan_id) ON DELETE CASCADE" +
            ");";

    Connection connection;
    public void initConnection(String path, String name) {
        String url = "jdbc:sqlite:" + path + "/" + name;
        try {
            Connection conn = DriverManager.getConnection(url);
            if (conn != null) {
                this.connection = conn;
                logger.log(LogLevel.INFO, "SQL connection established.");
            }

        } catch (SQLException e) {
            logger.log(LogLevel.WARN, "Fehler 4 " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public void createTables() {
        if(connection == null) {
            logger.log(LogLevel.WARN, "No connection established!");
            throw new RuntimeException("No connection established!");
        }
        for(String s : new String[]{createRepositoryTable, createVulnerabilityTable,createScanTable, createOccurrenceTable})
        try {
            Statement statement = connection.createStatement();
            statement.execute(s);
            statement.close();

        }
        catch (SQLException e) {
            logger.log(LogLevel.WARN, "SQL Exception while creating table: " + e);
            throw new RuntimeException(e);
        }
    }

    public int addScan(Date date, long repoID) {
        String insertScanSql = "INSERT INTO Scan(scan_date, repository_id ) VALUES (?, ?)";
        try {
            PreparedStatement insertScan = connection.prepareStatement(insertScanSql, Statement.RETURN_GENERATED_KEYS);
            insertScan.setString(1, formatDate(date));
            insertScan.setLong(2, repoID);
            insertScan.executeUpdate();
            ResultSet keys = insertScan.getGeneratedKeys();
            keys.next();
            int result = keys.getInt(1);
            insertScan.close();
            return result;
        }
        catch (SQLException e) {
            logger.log(LogLevel.WARN, "SQL Exception inserting a Scan with the date "+ date+": " + e);
            throw new RuntimeException(e);
        }

    }

    public void addVulnerability(long repositoryID, Date date, Vulnerability vulnerability, VulnerabilityScanner vulnerabilityScanner, int scanID) {
        String selectVulnSQL = "SELECT * FROM Vulnerability WHERE cve_id = ?";
        String selectVulnWhereScopeNotSetSQL = "SELECT * FROM Vulnerability WHERE cve_id = ? AND scope = NULL";
        String insertVulnSQL = "INSERT INTO Vulnerability(cve_id, cvss3_score, severity, published_at, Cwe_IDs, scope) " +
                "VALUES (?, ?, ?, ?, ?, ?)";
        String updateScopeAndCvssSQL = "UPDATE Vulnerability SET scope = ?, cvss3_score = ?, published_at = ? WHERE cve_id = ?";

        try {
            //einige Vulns haben keine CVE-ID, diese bekommen eine ID nach dem Schema "NONE_" + Zahl
            if(vulnerability.getCveIdentifier() == null) {
                String selectPreviousNoneSQL = "SELECT * FROM Vulnerability WHERE cve_id LIKE \"NONE%\" AND published_at = ?";
                PreparedStatement selectPreviousNone = connection.prepareStatement(selectPreviousNoneSQL);
                selectPreviousNone.setString(1, vulnerability.getPublishedAtAsString());
                ResultSet rs = selectPreviousNone.executeQuery();
                if(rs.next()) {
                    vulnerability.setCveIdentifier(rs.getString("cve_id"));
                }
                else {
                    vulnerability.setCveIdentifier("NONE" + vulnsWithoutCVE);
                    vulnsWithoutCVE++;
                }
                selectPreviousNone.close();
            }
            // if vulnerability doesn't exist, add it
            PreparedStatement selectVuln  = connection.prepareStatement(selectVulnSQL);
            selectVuln.setString(1, vulnerability.getCveIdentifier());
            PreparedStatement selectVulnWhereScopeNull  = connection.prepareStatement(selectVulnWhereScopeNotSetSQL);
            selectVuln.setString(1, vulnerability.getCveIdentifier());
            if(!selectVuln.executeQuery().next()) {
                PreparedStatement addVuln = connection.prepareStatement(insertVulnSQL);
                addVuln.setString(1, vulnerability.getCveIdentifier());
                addVuln.setDouble(2, vulnerability.getCvssScore());
                addVuln.setString(3, vulnerability.getSeverity());
                addVuln.setString(4, vulnerability.getPublishedAtAsString());
                addVuln.setString(5, vulnerability.getCWEIdsAsString());
                addVuln.setString(6, vulnerability.getScope());
                addVuln.executeUpdate();
                addVuln.close();
            }
            // if it exists bu doesn't have a scope, add scope CVSS and published_at
            else if(vulnerability.getScope() != null && !selectVulnWhereScopeNull.executeQuery().next()) {
                PreparedStatement updateVuln = connection.prepareStatement(updateScopeAndCvssSQL);
                updateVuln.setString(1, vulnerability.getScope());
                updateVuln.setDouble(2, vulnerability.getCvssScore());
                updateVuln.setString(3, vulnerability.getPublishedAtAsString());
                updateVuln.setString(4, vulnerability.getCveIdentifier());
                updateVuln.executeUpdate();
                updateVuln.close();
            }
            selectVuln.close();
            selectVulnWhereScopeNull.close();
        }
        catch (SQLException e) {
            throw new RuntimeException(e);
        }
        String selectOccurenceSQL = "SELECT * FROM Occurrence WHERE cve_id = ? AND repository_id = ? AND date = ? AND found_by = ?";
        String insertOccurrenceSQL = "INSERT INTO Occurrence(cve_id, repository_id, date, found_by, cpe_confidence, evidence_count, scan_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
        // add specific Occurence
        try {
            PreparedStatement selectOccurrence = connection.prepareStatement(selectOccurenceSQL);
            selectOccurrence.setString(1, vulnerability.getCveIdentifier());
            selectOccurrence.setLong(2, repositoryID);
            selectOccurrence.setString(3, formatDate(date));
            selectOccurrence.setString(4, vulnerabilityScanner.name());

            if(!selectOccurrence.executeQuery().next()) {
                PreparedStatement insertOccurrence = connection.prepareStatement(insertOccurrenceSQL);
                insertOccurrence.setString(1, vulnerability.getCveIdentifier());
                insertOccurrence.setLong(2, repositoryID);
                insertOccurrence.setString(3, formatDate(date));
                insertOccurrence.setString(4, vulnerabilityScanner.name());
                insertOccurrence.setString(5, vulnerability.getCpeConfidence());
                if (vulnerability.getEvidenceCount() != null) {
                    insertOccurrence.setInt(6, vulnerability.getEvidenceCount());
                }
                insertOccurrence.setInt(7, scanID);

                insertOccurrence.executeUpdate();
                insertOccurrence.close();
            }
            selectOccurrence.close();
            /*
            logger.log(LogLevel.DEBUG, "Inserted Occurence ("+
                    vulnerability.getCveIdentifier() +", " +
                    repositoryID +", " +
                    formatDate(date) +", " +
                    vulnerabilityScanner.name() +", " +
                    vulnerability.getCpeConfidence()+", " +
                    vulnerability.getEvidenceCount()+")");

             */

        }
        catch (SQLException e) {
            logger.log(LogLevel.WARN, "SQL Exception while inserting Occurrence ("+
                    vulnerability.getCveIdentifier() +", " +
                    repositoryID +", " +
                    formatDate(date) +", " +
                    vulnerabilityScanner.name() +", " +
                    vulnerability.getCpeConfidence()+", " +
                    vulnerability.getEvidenceCount()+") "+
                            ": " + e);
            throw new RuntimeException(e);
        }
    }

    public void addRepository(GHRepository repository) {
        String selectRepoSQL = "SELECT * FROM Repository WHERE repository_id = ?";
        String addRespositorySQL = "INSERT INTO Repository (repository_id, original_owner, name, creation_date, size) VALUES (?,?,?,?,?)";
        try {
            PreparedStatement selectRepo = connection.prepareStatement(selectRepoSQL);
            selectRepo.setLong(1, repository.getId());
            if(selectRepo.executeQuery().next()){
                selectRepo.close();
                return;
            }
            selectRepo.close();
            PreparedStatement insertRepository = connection.prepareStatement(addRespositorySQL);
            insertRepository.setLong(1, repository.getId());
            insertRepository.setString(2, repository.getOwnerName());
            insertRepository.setString(3, repository.getName());
            insertRepository.setString(4, formatDate(repository.getCreatedAt()));
            insertRepository.setInt(5, repository.getSize());
            insertRepository.executeUpdate();
            insertRepository.close();
        }
        catch (SQLException | IOException e) {
            logger.log(LogLevel.WARN, "SQL Exception while adding Reposiory "+repository.getFullName()+"; " + e);
            throw new RuntimeException(e);
        }

    }

    public void closeConnection() {
        try {
            connection.close();
        }
        catch (SQLException e) {
            logger.log(LogLevel.WARN, "SQL Exception while closing the Connection: " + e);
            throw new RuntimeException(e);
        }

    }

    public void addVulnerabilities(long repositoryID, Date date, Vulnerability[] vulnerabilities, VulnerabilityScanner vulnerabilityScanner, int scanID) {
        if(vulnerabilities == null) {
            logger.log(LogLevel.WARN, "[SQlite] No Vulnerabilities saved for " + repositoryID + " and " + date);
            return;
        }
        for(Vulnerability vulnerability : vulnerabilities) {
            addVulnerability(repositoryID, date, vulnerability, vulnerabilityScanner, scanID);
        }
    }

    private String formatDate(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(date);
    }
}

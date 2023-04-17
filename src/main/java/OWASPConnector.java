import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

public class OWASPConnector {

    public static Vulnerability[] loadOWASPVulns(String path) throws IOException, ParserConfigurationException, SAXException {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = builder.parse(new File(path));
        doc.getDocumentElement().normalize();
        NodeList vulnerabilityNodes = doc.getElementsByTagName("vulnerability");
        int numberOfNodes = vulnerabilityNodes.getLength();
        for(int i = 0; i < numberOfNodes; i++) {
            Vulnerability vulnerability = new Vulnerability();
            NodeList vulnNodeChildren = vulnerabilityNodes.item(i).getChildNodes();
            int numberChildren = vulnNodeChildren.getLength();
            for(int j = 0; j < numberChildren; j++) {
                Node child = vulnNodeChildren.item(j);
                switch (child.getNodeName()) {
                    case "name":
                        vulnerability.setCveIdentifier(child.getTextContent());
                        break;
                    case "severity":
                        vulnerability.setSeverity(child.getTextContent());
                        break;
                    case "cvssV3":
                        vulnerability.setCvssScore(Double.parseDouble(child.getFirstChild().getTextContent()));
                        break;
                    case "cwes":
                        vulnerability.setCweIds(IntStream.range(0, child.getChildNodes().getLength())
                                .mapToObj(child.getChildNodes()::item)
                                .map(Node::getTextContent)
                                .toArray(String[]::new));
                        break;
                }
            }
            vulnerabilities.add(vulnerability);
        }
        return vulnerabilities.toArray(Vulnerability[]::new);
    }

    public static Vulnerability[] loadOWASPVulnsCSV(String path) throws IOException {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
            String[][] rawResults = loadOwaspCsv("tmp/dependency-check-report.csv", ",");
            for (String[] line : rawResults) {
                int severityIndex = line.length - 5;
                int cvsIndex = line.length - 4;
                int cpeConfidenceIndex = line.length - 2;
                int evidenceCountIndex = line.length - 1;
                if (!line[0].contains("Project")) {
                    Vulnerability vulnerability = new Vulnerability();
                    vulnerability.setCveIdentifier(line[10]);
                    vulnerability.setCweIds(new String[]{line[11].split(" ")[0]});
                    if (!line[severityIndex].isBlank() && !line[severityIndex].matches("[\"]*")) {
                        vulnerability.setSeverity(line[severityIndex]);
                    }
                    if (!line[cvsIndex].isBlank() && !line[cvsIndex].matches("[\"]*")) {
                        vulnerability.setCvssScore(Double.parseDouble(line[cvsIndex]));
                    }
                    vulnerability.setCpeConfidence(line[cpeConfidenceIndex]);
                    vulnerability.setEvidenceCount(Integer.parseInt(line[evidenceCountIndex]));
                    vulnerabilities.add(vulnerability);
                }
            }
        return vulnerabilities.toArray(Vulnerability[]::new);
    }
        // filters ", " to " " to filter out commas in the free text
        private static String[][] loadOwaspCsv(String path, String separator) throws IOException {
            BufferedReader reader = new BufferedReader(new FileReader(path));
            String[][] lines = reader.lines().map(line -> line.replace(", ", " ")).map(line -> line.split(separator)).toArray(String[][]::new);
            reader.close();
            return lines;
        }
}

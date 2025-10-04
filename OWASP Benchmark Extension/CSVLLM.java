public class CSVLLM extends Reader {
 
    private final Map<String, Integer> categoryMappings = new HashMap<>();
 
    public CSVLLM() {}
 
    // Check if the file is a CSV and has the expected header
    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv") && resultFile.line(0).contains("# test name");
    }

    // Parse the CSV file and convert each record to a TestCaseResult
    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults(resultFile.filename(), false, TestSuiteResults.ToolType.SAST);
 
        try (CSVParser records = resultFile.csvRecordsSkipFirstRows(headerRow(resultFile))) {
            records.stream().forEach(r -> tr.put(toTestCaseResult(r)));
        }
 
        return tr;
    }

    // Find the header row index
    private int headerRow(ResultFile resultFile) {
        List<String> rows = resultFile.contentAsRows();
 
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).startsWith("# test name")) { 
                return i;
            }
        }
 
        throw new RuntimeException("No header row found");
    }
 
    // Extract test number from filename
    private TestCaseResult toTestCaseResult(CSVRecord record) {
        
        String filename = record.get("# test name");
        String category = record.get("category");
        String rVuln = record.get("real vulnerability");
        String CWE = record.get("cwe");
 
        TestCaseResult tcr = new TestCaseResult();
 
        tcr.setCategory(category);
        tcr.setCWE(extractNumberOrZero(CWE));
        tcr.setNumber(testNumber(filename));
        tcr.setRVuln(rVuln != null && rVuln.equalsIgnoreCase("TRUE"));
 
        return tcr;
    }
 
    // Extract test number from filename using regex
    private int extractNumberOrZero(String str) {
        if (str == null) return 0;
        Pattern p = Pattern.compile("(\\d+)");
        Matcher m = p.matcher(str);
        if (m.find()) {
            try {
                long value = Long.parseLong(m.group(1));
                if (value > Integer.MAX_VALUE) {
                    return Integer.MAX_VALUE;
                }
                return (int) value;
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }
}

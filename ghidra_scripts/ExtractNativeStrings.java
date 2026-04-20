// ExtractNativeStrings.java
// Ghidra headless script — extracts strings and function names from native libs
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser;
import java.io.*;
import java.util.*;

public class ExtractNativeStrings extends GhidraScript {

    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();
        String outputPath = "D:\\Major_Project\\ghidra_output\\" + programName + "_analysis.txt";
        
        new File("D:\\Major_Project\\ghidra_output").mkdirs();
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));

        out.println("=== Ghidra Native Analysis: " + programName + " ===");
        out.println("Analyzed: " + new Date());
        out.println();

        // ── 1. Exported function names ────────────────────
        out.println("--- EXPORTED FUNCTIONS ---");
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator extSymbols = symTable.getExternalSymbols();
        int exportCount = 0;
        SymbolIterator allSymbols = symTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol sym = allSymbols.next();
            if (sym.isExternalEntryPoint() || sym.getSymbolType() == SymbolType.FUNCTION) {
                String name = sym.getName();
                // Flag suspicious function names
                boolean suspicious = name.toLowerCase().matches(
                    ".*(sms|call|record|audio|camera|location|gps|contact|" +
                    "upload|exfil|keylog|hook|inject|root|su|hide|stealth|" +
                    "telegram|bot|c2|command|dlopen|dlsym).*"
                );
                if (suspicious) {
                    out.println("[SUSPICIOUS] " + name + " @ " + sym.getAddress());
                } else {
                    out.println("  " + name + " @ " + sym.getAddress());
                }
                exportCount++;
            }
        }
        out.println("Total functions: " + exportCount);
        out.println();

        // ── 2. String extraction ──────────────────────────
        out.println("--- STRINGS (length >= 8) ---");
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        
        List<String> suspiciousStrings = new ArrayList<>();
        List<String> urlStrings = new ArrayList<>();
        List<String> allStrings = new ArrayList<>();

        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            DataType dt = data.getDataType();
            if (dt instanceof StringDataType || 
                dt instanceof TerminatedStringDataType ||
                dt instanceof UnicodeDataType) {
                Object val = data.getValue();
                if (val != null) {
                    String s = val.toString().trim();
                    if (s.length() >= 8) {
                        allStrings.add(s + " [@ " + data.getAddress() + "]");
                        
                        // Flag URLs
                        if (s.startsWith("http") || s.startsWith("ws://") || 
                            s.contains("://")) {
                            urlStrings.add(s);
                        }
                        
                        // Flag suspicious keywords
                        String lower = s.toLowerCase();
                        if (lower.matches(".*(telegram|bot|token|c2|api|upload|" +
                                "exfil|sms|camera|record|location|password|" +
                                "keylog|hook|inject|root|su|magisk|frida|" +
                                "xposed|hide|stealth|socket|connect).*")) {
                            suspiciousStrings.add(s + " [@ " + data.getAddress() + "]");
                        }
                    }
                }
            }
        }

        out.println("--- URLS FOUND ---");
        if (urlStrings.isEmpty()) {
            out.println("  None found");
        } else {
            for (String u : urlStrings) out.println("  " + u);
        }
        out.println();

        out.println("--- SUSPICIOUS STRINGS ---");
        if (suspiciousStrings.isEmpty()) {
            out.println("  None matched keywords");
        } else {
            for (String s : suspiciousStrings) out.println("  " + s);
        }
        out.println();

        out.println("--- ALL STRINGS (first 100) ---");
        int count = 0;
        for (String s : allStrings) {
            if (count++ >= 100) break;
            out.println("  " + s);
        }
        out.println("Total strings extracted: " + allStrings.size());
        out.println();

        // ── 3. dlopen/dlsym detection ─────────────────────
        out.println("--- DYNAMIC LOADING (dlopen/dlsym) ---");
        SymbolIterator symIter = symTable.getAllSymbols(true);
        boolean foundDynLoad = false;
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            String name = sym.getName().toLowerCase();
            if (name.contains("dlopen") || name.contains("dlsym") || 
                name.contains("loadlibrary") || name.contains("system.load")) {
                out.println("  [DYNAMIC LOAD] " + sym.getName() + " @ " + sym.getAddress());
                foundDynLoad = true;
            }
        }
        if (!foundDynLoad) out.println("  None detected");

        out.println();
        out.println("=== Analysis Complete ===");
        out.close();
        println("Output written to: " + outputPath);
    }
}
// @category Codex
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ProbeDecompileStyles extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String addressText = getScriptArgs()[0];
        Address address = currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(addressText);
        Function function =
            currentProgram.getFunctionManager().getFunctionAt(address);
        for (String style : new String[] {
                "decompile", "normalize", "firstpass", "register", "paramid" }) {
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(true);
                decompiler.setSimplificationStyle(style);
                DecompileOptions options = new DecompileOptions();
                options.grabFromProgram(currentProgram);
                decompiler.setOptions(options);
                decompiler.openProgram(currentProgram);
                DecompileResults results =
                    decompiler.decompileFunction(function, 60, monitor);
                DecompiledFunction output = results.getDecompiledFunction();
                int cLength =
                    output == null || output.getC() == null ? 0 : output.getC().length();
                println("STYLE_RESULT style=" + style +
                    " completed=" + results.decompileCompleted() +
                    " timedOut=" + results.isTimedOut() +
                    " cLength=" + cLength +
                    " error=" + results.getErrorMessage().replace("\n", " | "));
            }
            finally {
                decompiler.dispose();
            }
        }
    }
}

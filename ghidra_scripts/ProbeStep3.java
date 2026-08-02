// @category Codex
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ProbeStep3 extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long iterated = 0;
        long external = 0;
        long memory = 0;
        FunctionIterator iterator =
            currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            iterated++;
            if (function.isExternal()) {
                external++;
            }
            else if (currentProgram.getMemory().contains(function.getEntryPoint())) {
                memory++;
            }
        }
        println("STEP3_PROBE program=" + currentProgram.getName() +
            " total=" + currentProgram.getFunctionManager().getFunctionCount() +
            " iterated=" + iterated + " external=" + external +
            " memory=" + memory);
    }
}

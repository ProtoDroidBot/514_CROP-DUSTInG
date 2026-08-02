// Prints an exact instruction/byte listing for one function.
// @category Dust514

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.util.Iterator;

public class PrintFunctionListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: PrintFunctionListing.java <hex-entry>");
        }
        long value = Long.parseUnsignedLong(args[0].replaceFirst("^(0x|0X)", ""), 16);
        Address entry = toAddr(value);
        Function function = getFunctionAt(entry);
        if (function == null) {
            throw new IllegalStateException("no function at " + entry);
        }
        println("FUNCTION " + function.getName() + " " + function.getEntryPoint() +
                ".." + function.getBody().getMaxAddress());
        Iterator<Instruction> instructions = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            byte[] bytes = instruction.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b & 0xff));
            }
            println(String.format("%s  %-8s  %s", instruction.getAddress(), hex,
                    instruction.toString()));
        }
    }
}

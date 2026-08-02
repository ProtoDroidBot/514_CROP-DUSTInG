// @category Codex
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.zip.GZIPOutputStream;

/**
 * Export an exact, non-decompiler fallback for selected functions.
 *
 * Arguments:
 *   0: function-summary JSONL.GZ output path
 *   1: instruction JSONL.GZ output path
 *   2+: internal function entry points
 */
public class ExportStep3Fallbacks extends GhidraScript {
    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    }
                    else {
                        out.append(c);
                    }
            }
        }
        return out.append('"').toString();
    }

    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            result[i * 2] = digits[value >>> 4];
            result[i * 2 + 1] = digits[value & 0xf];
        }
        return new String(result);
    }

    private static String sha256(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hex(digest.digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    private static BufferedWriter gzipWriter(String path) throws Exception {
        return new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(new FileOutputStream(path)), StandardCharsets.UTF_8),
            1024 * 1024);
    }

    private String rangesJson(Function function) {
        StringBuilder out = new StringBuilder("[");
        AddressRangeIterator ranges = function.getBody().getAddressRanges(true);
        boolean first = true;
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (!first) out.append(',');
            first = false;
            out.append("{\"min\":").append(json(range.getMinAddress().toString()))
                .append(",\"max\":").append(json(range.getMaxAddress().toString()))
                .append(",\"length\":").append(range.getLength()).append('}');
        }
        return out.append(']').toString();
    }

    private String operandsJson(Instruction instruction) {
        StringBuilder out = new StringBuilder("[");
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            if (index != 0) out.append(',');
            int type = instruction.getOperandType(index);
            out.append("{\"index\":").append(index)
                .append(",\"representation\":")
                .append(json(instruction.getDefaultOperandRepresentation(index)))
                .append(",\"type_bits\":").append(type)
                .append(",\"is_address\":").append(OperandType.isAddress(type))
                .append(",\"is_scalar\":").append(OperandType.isScalar(type))
                .append(",\"is_register\":").append(OperandType.isRegister(type))
                .append('}');
        }
        return out.append(']').toString();
    }

    private String pcodeJson(Instruction instruction) {
        StringBuilder out = new StringBuilder("[");
        PcodeOp[] ops = instruction.getPcode();
        for (int index = 0; index < ops.length; index++) {
            if (index != 0) out.append(',');
            out.append(json(ops[index].toString()));
        }
        return out.append(']').toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException(
                "Expected summary path, instruction path, and at least one entry point");
        }

        int exportedFunctions = 0;
        long exportedInstructions = 0;
        long exportedPcodeOps = 0;

        try (BufferedWriter summaries = gzipWriter(args[0]);
             BufferedWriter instructions = gzipWriter(args[1])) {
            for (int argIndex = 2; argIndex < args.length; argIndex++) {
                monitor.checkCancelled();
                Address entry = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(args[argIndex]);
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (function == null) {
                    throw new IllegalStateException("No internal function at " + args[argIndex]);
                }

                long symbolId = function.getSymbol().getID();
                long instructionCount = 0;
                long pcodeCount = 0;
                StringBuilder assemblyDigestInput = new StringBuilder();
                StringBuilder pcodeDigestInput = new StringBuilder();
                InstructionIterator iterator = currentProgram.getListing()
                    .getInstructions(function.getBody(), true);
                while (iterator.hasNext()) {
                    monitor.checkCancelled();
                    Instruction instruction = iterator.next();
                    byte[] bytes = instruction.getBytes();
                    PcodeOp[] pcode = instruction.getPcode();
                    FlowType flowType = instruction.getFlowType();
                    Address fallThrough = instruction.getFallThrough();
                    String address = instruction.getAddress().toString();
                    String instructionText = instruction.toString();
                    String bytesHex = hex(bytes);
                    String pcodeArray = pcodeJson(instruction);

                    instructions.write("{\"schema_version\":1");
                    instructions.write(",\"symbol_id\":" + symbolId);
                    instructions.write(",\"function_entry\":" + json(entry.toString()));
                    instructions.write(",\"address\":" + json(address));
                    instructions.write(",\"length\":" + instruction.getLength());
                    instructions.write(",\"bytes_hex\":" + json(bytesHex));
                    instructions.write(",\"mnemonic\":" + json(instruction.getMnemonicString()));
                    instructions.write(",\"text\":" + json(instructionText));
                    instructions.write(",\"operands\":" + operandsJson(instruction));
                    instructions.write(",\"flow_type\":" +
                        json(flowType == null ? null : flowType.toString()));
                    instructions.write(",\"fall_through\":" +
                        json(fallThrough == null ? null : fallThrough.toString()));
                    instructions.write(",\"delay_slot_depth\":" + instruction.getDelaySlotDepth());
                    instructions.write(",\"raw_pcode\":" + pcodeArray + "}\n");

                    assemblyDigestInput.append(address).append('|').append(bytesHex)
                        .append('|').append(instructionText).append('\n');
                    for (PcodeOp op : pcode) {
                        pcodeDigestInput.append(op.toString()).append('\n');
                    }
                    instructionCount++;
                    pcodeCount += pcode.length;
                }

                summaries.write("{\"schema_version\":1");
                summaries.write(",\"ghidra_version\":" +
                    json(ghidra.framework.Application.getApplicationVersion()));
                summaries.write(",\"symbol_id\":" + symbolId);
                summaries.write(",\"entry_point\":" + json(entry.toString()));
                summaries.write(",\"name\":" + json(function.getName()));
                summaries.write(",\"body_ranges\":" + rangesJson(function));
                summaries.write(",\"instruction_count\":" + instructionCount);
                summaries.write(",\"raw_pcode_op_count\":" + pcodeCount);
                summaries.write(",\"assembly_sha256\":" +
                    json(sha256(assemblyDigestInput.toString())));
                summaries.write(",\"raw_pcode_sha256\":" +
                    json(sha256(pcodeDigestInput.toString())));
                summaries.write(",\"fallback_kind\":\"exact_bytes_disassembly_raw_pcode\"}\n");

                exportedFunctions++;
                exportedInstructions += instructionCount;
                exportedPcodeOps += pcodeCount;
                println("STEP3_FALLBACK function=" + entry + " instructions=" +
                    instructionCount + " rawPcodeOps=" + pcodeCount);
            }
        }

        println("STEP3_FALLBACK_DONE functions=" + exportedFunctions +
            " instructions=" + exportedInstructions + " rawPcodeOps=" + exportedPcodeOps);
    }
}

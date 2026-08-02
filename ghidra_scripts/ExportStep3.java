// @category Codex

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.GZIPOutputStream;

import com.google.gson.*;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class ExportStep3 extends GhidraScript {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private static class GzipJsonlWriter implements Closeable {
        private final BufferedWriter writer;

        GzipJsonlWriter(Path path) throws IOException {
            OutputStream output = Files.newOutputStream(path);
            GZIPOutputStream gzip = new GZIPOutputStream(output, 1024 * 1024);
            writer = new BufferedWriter(
                new OutputStreamWriter(gzip, StandardCharsets.UTF_8),
                1024 * 1024);
        }

        void write(JsonObject object) throws IOException {
            writer.write(GSON.toJson(object));
            writer.newLine();
        }

        @Override
        public void close() throws IOException {
            writer.close();
        }
    }

    private static class ShardStats {
        int functions;
        long instructions;
        long outgoingReferences;
        long incomingReferences;
        long stringReferences;
        long distinctConstants;
        int decompileCompleted;
        int decompileFailed;
        int decompileTimedOut;
    }

    private static class DecompileRecord {
        String entryPoint;
        JsonObject json;

        DecompileRecord(String entryPoint, JsonObject json) {
            this.entryPoint = entryPoint;
            this.json = json;
        }
    }

    private static class ConstantCount {
        int bitLength;
        long unsignedValue;
        long signedValue;
        boolean signed;
        long occurrences;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Usage: ExportStep3.java <outputDir> [shardSize] [maxFunctions]");
        }
        Path outputDirectory = Paths.get(args[0]).toAbsolutePath().normalize();
        int shardSize = args.length >= 2 ? Integer.parseInt(args[1]) : 500;
        int maxFunctions = args.length >= 3 ? Integer.parseInt(args[2]) : 0;
        if (shardSize < 1) {
            throw new IllegalArgumentException("shardSize must be positive");
        }
        Files.createDirectories(outputDirectory);

        List<ghidra.program.model.listing.Function> functions = new ArrayList<>();
        FunctionIterator iterator =
            currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            ghidra.program.model.listing.Function function = iterator.next();
            if (function.isExternal()) {
                continue;
            }
            if (!currentProgram.getMemory().contains(function.getEntryPoint())) {
                continue;
            }
            functions.add(function);
            if (maxFunctions > 0 && functions.size() >= maxFunctions) {
                break;
            }
        }
        functions.sort(Comparator.comparing(
            ghidra.program.model.listing.Function::getEntryPoint));

        println("STEP3_EXPORT version=" + currentProgram.getExecutableFormat() +
            " functions=" + functions.size() + " shardSize=" + shardSize +
            " output=" + outputDirectory);

        int shardCount = (functions.size() + shardSize - 1) / shardSize;
        int completedShards = 0;
        for (int shardIndex = 0; shardIndex < shardCount; shardIndex++) {
            monitor.checkCancelled();
            int start = shardIndex * shardSize;
            int end = Math.min(functions.size(), start + shardSize);
            List<ghidra.program.model.listing.Function> shard =
                new ArrayList<>(functions.subList(start, end));
            String prefix = String.format("shard-%05d", shardIndex);
            Path donePath = outputDirectory.resolve(prefix + ".done.json");
            if (Files.exists(donePath)) {
                completedShards++;
                println("STEP3_SHARD skip=" + shardIndex + " completed=" +
                    completedShards + "/" + shardCount);
                continue;
            }
            exportShard(outputDirectory, prefix, shard, shardIndex, shardCount);
            completedShards++;
            println("STEP3_SHARD complete=" + shardIndex + " completed=" +
                completedShards + "/" + shardCount);
        }
        println("STEP3_EXPORT_DONE shards=" + completedShards +
            " functions=" + functions.size());
    }

    private void exportShard(Path outputDirectory, String prefix,
            List<ghidra.program.model.listing.Function> shard,
            int shardIndex, int shardCount) throws Exception {

        Path metadataPart = outputDirectory.resolve(prefix + ".metadata.jsonl.gz.part");
        Path referencesPart = outputDirectory.resolve(prefix + ".references.jsonl.gz.part");
        Path decompPart = outputDirectory.resolve(prefix + ".decompilations.jsonl.gz.part");
        Path metadataFinal = outputDirectory.resolve(prefix + ".metadata.jsonl.gz");
        Path referencesFinal = outputDirectory.resolve(prefix + ".references.jsonl.gz");
        Path decompFinal = outputDirectory.resolve(prefix + ".decompilations.jsonl.gz");
        Path donePath = outputDirectory.resolve(prefix + ".done.json");
        Files.deleteIfExists(metadataPart);
        Files.deleteIfExists(referencesPart);
        Files.deleteIfExists(decompPart);

        ShardStats stats = new ShardStats();
        try (GzipJsonlWriter metadataWriter = new GzipJsonlWriter(metadataPart);
             GzipJsonlWriter referenceWriter = new GzipJsonlWriter(referencesPart)) {
            for (ghidra.program.model.listing.Function function : shard) {
                monitor.checkCancelled();
                JsonObject metadata =
                    buildFunctionMetadata(function, referenceWriter, stats);
                metadataWriter.write(metadata);
                stats.functions++;
            }
        }

        List<DecompileRecord> decompilations = decompileShard(shard);
        decompilations.sort(Comparator.comparing(record -> record.entryPoint));
        try (GzipJsonlWriter decompWriter = new GzipJsonlWriter(decompPart)) {
            for (DecompileRecord record : decompilations) {
                decompWriter.write(record.json);
                if (record.json.get("completed").getAsBoolean()) {
                    stats.decompileCompleted++;
                }
                else {
                    stats.decompileFailed++;
                    if (record.json.get("timed_out").getAsBoolean()) {
                        stats.decompileTimedOut++;
                    }
                }
            }
        }

        moveCompleted(metadataPart, metadataFinal);
        moveCompleted(referencesPart, referencesFinal);
        moveCompleted(decompPart, decompFinal);

        JsonObject done = new JsonObject();
        done.addProperty("schema_version", 1);
        done.addProperty("shard_index", shardIndex);
        done.addProperty("shard_count", shardCount);
        done.addProperty("function_count", stats.functions);
        done.addProperty("first_entry_point", shard.get(0).getEntryPoint().toString());
        done.addProperty("last_entry_point",
            shard.get(shard.size() - 1).getEntryPoint().toString());
        done.addProperty("instruction_count", stats.instructions);
        done.addProperty("outgoing_reference_count", stats.outgoingReferences);
        done.addProperty("incoming_reference_count", stats.incomingReferences);
        done.addProperty("string_reference_count", stats.stringReferences);
        done.addProperty("distinct_constant_count", stats.distinctConstants);
        done.addProperty("decompile_completed", stats.decompileCompleted);
        done.addProperty("decompile_failed", stats.decompileFailed);
        done.addProperty("decompile_timed_out", stats.decompileTimedOut);
        Files.writeString(donePath, GSON.toJson(done) + "\n",
            StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    private JsonObject buildFunctionMetadata(
            ghidra.program.model.listing.Function function,
            GzipJsonlWriter referenceWriter, ShardStats stats) throws Exception {

        Listing listing = currentProgram.getListing();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();

        JsonObject json = functionIdentity(function);
        json.addProperty("namespace", function.getParentNamespace().getName(true));
        json.addProperty("signature",
            function.getSignature().getPrototypeString());
        json.addProperty("signature_source",
            function.getSignatureSource().toString());
        json.addProperty("calling_convention", function.getCallingConventionName());
        json.addProperty("return_type",
            function.getReturnType().getDisplayName());
        json.addProperty("no_return", function.hasNoReturn());
        json.addProperty("var_args", function.hasVarArgs());
        json.addProperty("inline", function.isInline());
        json.addProperty("thunk", function.isThunk());

        ghidra.program.model.listing.Function thunked =
            function.getThunkedFunction(true);
        if (thunked != null) {
            json.add("thunk_target", functionIdentity(thunked));
        }
        else {
            json.add("thunk_target", JsonNull.INSTANCE);
        }

        AddressSetView body = function.getBody();
        JsonObject bodyJson = new JsonObject();
        bodyJson.addProperty("minimum", body.getMinAddress().toString());
        bodyJson.addProperty("maximum", body.getMaxAddress().toString());
        bodyJson.addProperty("address_count", body.getNumAddresses());
        JsonArray ranges = new JsonArray();
        AddressRangeIterator rangeIterator = body.getAddressRanges();
        while (rangeIterator.hasNext()) {
            AddressRange range = rangeIterator.next();
            JsonObject rangeJson = new JsonObject();
            rangeJson.addProperty("minimum", range.getMinAddress().toString());
            rangeJson.addProperty("maximum", range.getMaxAddress().toString());
            rangeJson.addProperty("length", range.getLength());
            ranges.add(rangeJson);
        }
        bodyJson.add("ranges", ranges);
        json.add("body", bodyJson);

        JsonArray parameters = new JsonArray();
        for (Parameter parameter : function.getParameters()) {
            JsonObject value = variableJson(parameter);
            value.addProperty("ordinal", parameter.getOrdinal());
            value.addProperty("auto_parameter", parameter.isAutoParameter());
            parameters.add(value);
        }
        json.add("parameters", parameters);

        JsonArray locals = new JsonArray();
        for (Variable variable : function.getLocalVariables()) {
            locals.add(variableJson(variable));
        }
        json.add("locals", locals);

        Set<ghidra.program.model.listing.Function> callers =
            function.getCallingFunctions(monitor);
        Set<ghidra.program.model.listing.Function> callees =
            function.getCalledFunctions(monitor);
        json.add("callers", functionSetJson(callers));
        json.add("callees", functionSetJson(callees));

        Map<String, Long> incomingByType = new TreeMap<>();
        long incomingCount = 0;
        ReferenceIterator incoming =
            referenceManager.getReferencesTo(function.getEntryPoint());
        while (incoming.hasNext()) {
            Reference reference = incoming.next();
            incomingCount++;
            String type = reference.getReferenceType().getName();
            incomingByType.merge(type, 1L, Long::sum);
            JsonObject referenceJson = buildReferenceJson(
                function, reference, functionManager, listing, "incoming");
            referenceWriter.write(referenceJson);
        }
        stats.incomingReferences += incomingCount;
        json.addProperty("incoming_reference_count", incomingCount);
        json.add("incoming_references_by_type", countMapJson(incomingByType));

        Map<String, Long> outgoingByType = new TreeMap<>();
        Map<String, ConstantCount> constants = new TreeMap<>();
        JsonArray strings = new JsonArray();
        long outgoingCount = 0;
        long instructionCount = 0;
        InstructionIterator instructions = listing.getInstructions(body, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            instructionCount++;
            collectConstants(instruction, constants);
            for (Reference reference : instruction.getReferencesFrom()) {
                outgoingCount++;
                String type = reference.getReferenceType().getName();
                outgoingByType.merge(type, 1L, Long::sum);
                JsonObject referenceJson =
                    buildReferenceJson(
                        function, reference, functionManager, listing, "outgoing");
                referenceWriter.write(referenceJson);
                if (referenceJson.has("string_value") &&
                        !referenceJson.get("string_value").isJsonNull()) {
                    JsonObject stringJson = new JsonObject();
                    stringJson.addProperty("from_address",
                        reference.getFromAddress().toString());
                    stringJson.addProperty("to_address",
                        reference.getToAddress().toString());
                    stringJson.add("value", referenceJson.get("string_value"));
                    if (referenceJson.has("target_data_type")) {
                        stringJson.add("data_type",
                            referenceJson.get("target_data_type"));
                    }
                    strings.add(stringJson);
                    stats.stringReferences++;
                }
            }
        }
        stats.instructions += instructionCount;
        stats.outgoingReferences += outgoingCount;
        stats.distinctConstants += constants.size();
        json.addProperty("instruction_count", instructionCount);
        json.addProperty("outgoing_reference_count", outgoingCount);
        json.add("outgoing_references_by_type", countMapJson(outgoingByType));
        json.add("string_references", strings);
        json.add("constants", constantsJson(constants));
        return json;
    }

    private JsonObject buildReferenceJson(
            ghidra.program.model.listing.Function owner,
            Reference reference, FunctionManager functionManager,
            Listing listing, String direction) {
        JsonObject json = new JsonObject();
        json.addProperty("owner_symbol_id", owner.getSymbol().getID());
        json.addProperty("owner_entry_point", owner.getEntryPoint().toString());
        json.addProperty("direction", direction);
        json.addProperty("from_address", reference.getFromAddress().toString());
        json.addProperty("to_address", reference.getToAddress().toString());
        json.addProperty("type", reference.getReferenceType().getName());
        json.addProperty("operand_index", reference.getOperandIndex());
        json.addProperty("primary", reference.isPrimary());
        json.addProperty("source", reference.getSource().toString());

        ghidra.program.model.listing.Function sourceFunction = null;
        if (reference.getFromAddress().isMemoryAddress()) {
            sourceFunction =
                functionManager.getFunctionContaining(reference.getFromAddress());
        }
        if (sourceFunction != null) {
            json.add("source_function", functionIdentity(sourceFunction));
        }
        else {
            json.add("source_function", JsonNull.INSTANCE);
        }

        ghidra.program.model.listing.Function target =
            functionManager.getFunctionAt(reference.getToAddress());
        if (target == null && reference.getToAddress().isMemoryAddress()) {
            target = functionManager.getFunctionContaining(reference.getToAddress());
        }
        if (target != null) {
            json.add("target_function", functionIdentity(target));
        }
        else {
            json.add("target_function", JsonNull.INSTANCE);
        }

        Data data = null;
        if (reference.getToAddress().isMemoryAddress()) {
            data = listing.getDataContaining(reference.getToAddress());
        }
        if (data != null) {
            json.addProperty("target_data_address", data.getAddress().toString());
            json.addProperty("target_data_type",
                data.getDataType().getDisplayName());
            if (data.hasStringValue()) {
                Object value = data.getValue();
                json.addProperty("string_value",
                    value == null ? null : String.valueOf(value));
            }
            else {
                json.add("string_value", JsonNull.INSTANCE);
            }
        }
        else {
            json.add("target_data_address", JsonNull.INSTANCE);
            json.add("target_data_type", JsonNull.INSTANCE);
            json.add("string_value", JsonNull.INSTANCE);
        }
        return json;
    }

    private List<DecompileRecord> decompileShard(
            Collection<ghidra.program.model.listing.Function> functions)
            throws Exception {
        DecompilerCallback<DecompileRecord> callback =
            new DecompilerCallback<>(currentProgram, decompiler -> {
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(true);
                decompiler.setSimplificationStyle("decompile");
                DecompileOptions options = new DecompileOptions();
                options.grabFromProgram(currentProgram);
                decompiler.setOptions(options);
            }) {
                @Override
                public DecompileRecord process(
                        DecompileResults results, TaskMonitor taskMonitor) {
                    ghidra.program.model.listing.Function function =
                        results.getFunction();
                    JsonObject json = functionIdentity(function);
                    boolean completed = results.decompileCompleted();
                    json.addProperty("completed", completed);
                    json.addProperty("timed_out", results.isTimedOut());
                    json.addProperty("cancelled", results.isCancelled());
                    json.addProperty("failed_to_start", results.failedToStart());
                    json.addProperty("error_message",
                        nullToEmpty(results.getErrorMessage()));
                    String cCode = null;
                    DecompiledFunction decompiled =
                        results.getDecompiledFunction();
                    if (decompiled != null) {
                        cCode = decompiled.getC();
                    }
                    if (cCode == null) {
                        json.add("c_code", JsonNull.INSTANCE);
                        json.add("c_code_sha256", JsonNull.INSTANCE);
                        json.addProperty("c_code_length", 0);
                    }
                    else {
                        json.addProperty("c_code", cCode);
                        json.addProperty("c_code_sha256", sha256(cCode));
                        json.addProperty("c_code_length", cCode.length());
                    }
                    long pcodeOps = 0;
                    Map<String, Long> pcodeConstants = new TreeMap<>();
                    JsonArray highSymbols = new JsonArray();
                    HighFunction high = results.getHighFunction();
                    if (high != null) {
                        Iterator<PcodeOpAST> operations = high.getPcodeOps();
                        while (operations.hasNext()) {
                            PcodeOpAST operation = operations.next();
                            pcodeOps++;
                            for (Varnode input : operation.getInputs()) {
                                if (input != null && input.isConstant()) {
                                    String key = input.getSize() + ":" +
                                        Long.toUnsignedString(
                                            input.getOffset(), 16);
                                    pcodeConstants.merge(key, 1L, Long::sum);
                                }
                            }
                        }
                        Iterator<HighSymbol> symbols =
                            high.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            HighSymbol symbol = symbols.next();
                            JsonObject symbolJson = new JsonObject();
                            symbolJson.addProperty("id",
                                Long.toUnsignedString(symbol.getId()));
                            symbolJson.addProperty("name", symbol.getName());
                            symbolJson.addProperty("data_type",
                                symbol.getDataType().getDisplayName());
                            symbolJson.addProperty("data_type_path",
                                symbol.getDataType().getPathName());
                            symbolJson.addProperty("size", symbol.getSize());
                            symbolJson.addProperty("storage",
                                symbol.getStorage().toString());
                            Address pcAddress = symbol.getPCAddress();
                            if (pcAddress != null) {
                                symbolJson.addProperty("pc_address",
                                    pcAddress.toString());
                            }
                            else {
                                symbolJson.add("pc_address", JsonNull.INSTANCE);
                            }
                            symbolJson.addProperty("parameter",
                                symbol.isParameter());
                            symbolJson.addProperty("category_index",
                                symbol.getCategoryIndex());
                            symbolJson.addProperty("global", symbol.isGlobal());
                            symbolJson.addProperty("this_pointer",
                                symbol.isThisPointer());
                            symbolJson.addProperty("hidden_return",
                                symbol.isHiddenReturn());
                            symbolJson.addProperty("name_locked",
                                symbol.isNameLocked());
                            symbolJson.addProperty("type_locked",
                                symbol.isTypeLocked());
                            highSymbols.add(symbolJson);
                        }
                    }
                    json.addProperty("high_pcode_op_count", pcodeOps);
                    json.add("high_symbols", highSymbols);
                    JsonArray pcodeConstantArray = new JsonArray();
                    for (Map.Entry<String, Long> entry :
                            pcodeConstants.entrySet()) {
                        String[] parts = entry.getKey().split(":", 2);
                        JsonObject constantJson = new JsonObject();
                        constantJson.addProperty("size_bytes",
                            Integer.parseInt(parts[0]));
                        constantJson.addProperty("unsigned_hex",
                            "0x" + parts[1]);
                        constantJson.addProperty("occurrences",
                            entry.getValue());
                        pcodeConstantArray.add(constantJson);
                    }
                    json.add("high_pcode_constants", pcodeConstantArray);
                    return new DecompileRecord(
                        function.getEntryPoint().toString(), json);
                }
            };
        callback.setTimeout(60);
        try {
            return ParallelDecompiler.decompileFunctions(
                callback, functions, monitor);
        }
        finally {
            callback.dispose();
        }
    }

    private JsonObject variableJson(Variable variable) {
        JsonObject json = new JsonObject();
        json.addProperty("name", variable.getName());
        DataType dataType = variable.getDataType();
        json.addProperty("data_type", dataType.getDisplayName());
        json.addProperty("data_type_path", dataType.getPathName());
        json.addProperty("length", variable.getLength());
        json.addProperty("storage", variable.getVariableStorage().toString());
        json.addProperty("first_use_offset", variable.getFirstUseOffset());
        json.addProperty("source", variable.getSource().toString());
        return json;
    }

    private JsonArray functionSetJson(
            Collection<ghidra.program.model.listing.Function> functions) {
        List<ghidra.program.model.listing.Function> sorted =
            new ArrayList<>(functions);
        sorted.sort(Comparator.comparing(
            ghidra.program.model.listing.Function::getEntryPoint));
        JsonArray array = new JsonArray();
        for (ghidra.program.model.listing.Function function : sorted) {
            array.add(functionIdentity(function));
        }
        return array;
    }

    private JsonObject functionIdentity(
            ghidra.program.model.listing.Function function) {
        JsonObject json = new JsonObject();
        json.addProperty("symbol_id", function.getSymbol().getID());
        json.addProperty("entry_point", function.getEntryPoint().toString());
        json.addProperty("name", function.getName(true));
        json.addProperty("external", function.isExternal());
        return json;
    }

    private JsonObject countMapJson(Map<String, Long> counts) {
        JsonObject json = new JsonObject();
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            json.addProperty(entry.getKey(), entry.getValue());
        }
        return json;
    }

    private void collectConstants(
            Instruction instruction, Map<String, ConstantCount> constants) {
        for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
            for (Object object : instruction.getOpObjects(operand)) {
                if (!(object instanceof Scalar)) {
                    continue;
                }
                Scalar scalar = (Scalar) object;
                long unsigned = scalar.getUnsignedValue();
                String key = scalar.bitLength() + ":" +
                    Long.toUnsignedString(unsigned, 16);
                ConstantCount count = constants.get(key);
                if (count == null) {
                    count = new ConstantCount();
                    count.bitLength = scalar.bitLength();
                    count.unsignedValue = unsigned;
                    count.signedValue = scalar.getSignedValue();
                    count.signed = scalar.isSigned();
                    constants.put(key, count);
                }
                count.occurrences++;
            }
        }
    }

    private JsonArray constantsJson(Map<String, ConstantCount> constants) {
        JsonArray array = new JsonArray();
        for (ConstantCount count : constants.values()) {
            JsonObject json = new JsonObject();
            json.addProperty("bit_length", count.bitLength);
            json.addProperty("unsigned_hex",
                "0x" + Long.toUnsignedString(count.unsignedValue, 16));
            json.addProperty("signed_decimal",
                Long.toString(count.signedValue));
            json.addProperty("is_signed", count.signed);
            json.addProperty("occurrences", count.occurrences);
            array.add(json);
        }
        return array;
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                result.append(String.format("%02x", b & 0xff));
            }
            return result.toString();
        }
        catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private void moveCompleted(Path part, Path completed) throws IOException {
        Files.move(part, completed, StandardCopyOption.REPLACE_EXISTING);
    }
}

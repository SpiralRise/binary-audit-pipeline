// Ghidra headless postScript: 导出当前程序的全部函数反编译伪代码
// 用法（由 analyzeHeadless 的 -postScript 调用）：
//   -postScript ExportDecompiled.java /work/out/04_pseudocode
// 参数：args[0] = 输出目录（可选，默认 /work/out/04_pseudocode）
// 产物：每个被分析的程序生成一个 <程序名>.c 文件，内含全部函数的 C 伪代码

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class ExportDecompiled extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outRoot = (args.length > 0 && args[0] != null && !args[0].isEmpty())
                ? args[0]
                : "/work/out/04_pseudocode";

        File dir = new File(outRoot);
        if (!dir.exists() && !dir.mkdirs()) {
            printerr("无法创建输出目录: " + outRoot);
            return;
        }

        String programName = currentProgram.getName();
        String safeName = programName.replaceAll("[^A-Za-z0-9._-]", "_");
        File outFile = new File(dir, safeName + ".c");

        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        if (!ifc.openProgram(currentProgram)) {
            printerr("反编译器无法打开程序: " + programName);
            return;
        }

        int ok = 0;
        int fail = 0;
        try (PrintWriter pw = new PrintWriter(outFile, "UTF-8")) {
            pw.println("// program : " + programName);
            pw.println("// language: " + currentProgram.getLanguageID());
            pw.println("// compiler: " + currentProgram.getCompiler());
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                pw.println();
                pw.println("// ===== function " + f.getName()
                        + " @ " + f.getEntryPoint() + " =====");
                try {
                    DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                    if (res != null && res.decompileCompleted()
                            && res.getDecompiledFunction() != null) {
                        pw.println(res.getDecompiledFunction().getC());
                        ok++;
                    } else {
                        pw.println("// [decompile failed] " + f.getName());
                        fail++;
                    }
                } catch (Exception e) {
                    pw.println("// [decompile exception] " + f.getName()
                            + " : " + e.getMessage());
                    fail++;
                }
            }
        } finally {
            ifc.dispose();
        }

        println("导出完成: " + ok + " 个函数成功, " + fail + " 个失败 -> "
                + outFile.getAbsolutePath());
    }
}

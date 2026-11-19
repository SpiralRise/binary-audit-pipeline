// Joern 污点可达性查询（可选步骤）
// 作用：在反编译伪代码的代码属性图(CPG)上，找「外部输入 source → 危险函数 sink」的可达数据流。
// 输出：每条数据流按 source → sink 顺序逐节点打印，格式为
//       [节点类型] 文件:行号  函数名  |  代码片段
//       这样能直接看出数据从哪个文件的哪个函数、哪段代码，流到哪个文件的哪个函数。
// 调用方式：
//   CPG_FILE=/work/out/06_joern/cpg.bin JOERN_OUT=/work/out/06_joern/taint_flows.txt \
//     JOERN_SINKS=/work/out/06_joern/semgrep_sinks.txt \
//     joern --script /opt/pipeline/scripts/taint_scan.sc
// sink 名单优先取 JOERN_SINKS（Semgrep 命中行提取），文件不存在时用下面的默认名单。
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, CfgNode, Method}
import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter
import scala.util.control.NonFatal

@main def main(): Unit = {
  val cpgFile = sys.env.getOrElse("CPG_FILE", "/work/out/06_joern/cpg.bin")
  val outFile = sys.env.getOrElse("JOERN_OUT", "/work/out/06_joern/taint_flows.txt")
  val sinksPath = sys.env.getOrElse("JOERN_SINKS", "/work/out/06_joern/semgrep_sinks.txt")

  importCpg(cpgFile)

  val defaultSinkNames = List("strcpy", "strcat", "sprintf", "memcpy", "memmove",
    "system", "popen", "execl", "execlp", "execv", "execvp")

  val extraSinks: List[String] =
    try {
      val f = new java.io.File(sinksPath)
      if (f.exists()) {
        scala.io.Source.fromFile(f, "UTF-8").getLines()
          .map(_.trim).filter(_.nonEmpty).toList.distinct
      } else List.empty[String]
    } catch { case NonFatal(_) => List.empty[String] }

  // source（外部输入）名单：这些函数的返回值/实参视为污点源
  val sourceNames = List("recv", "recvfrom", "read", "fread", "fgets", "gets",
    "scanf", "getenv", "BIO_read", "SSL_read", "SSL_get_message")

  val sinkNames = (if (extraSinks.nonEmpty) extraSinks else defaultSinkNames)
    .filterNot(n => sourceNames.contains(n)).distinct
  val sinkRegex = sinkNames.map(java.util.regex.Pattern.quote).mkString("(", "|", ")")

  // ---- 节点描述辅助函数：文件、函数、行号、代码 ----
  def oneLine(text: String, limit: Int = 200): String = {
    val t = if (text == null) "" else text.replaceAll("\\s+", " ").trim
    if (t.length > limit) t.take(limit) + " ..." else t
  }

  def lineOf(node: AstNode): String =
    try {
      val raw = String.valueOf(node.lineNumber)
      val stripped = raw.replaceAll("^Some\\((.*)\\)$", "$1").trim
      if (stripped.isEmpty || stripped == "null" || stripped == "None") "?" else stripped
    } catch { case NonFatal(_) => "?" }

  def methodOf(node: AstNode): Option[Method] =
    try {
      val m = node.asInstanceOf[CfgNode].method
      if (m == null) None else Some(m)
    } catch { case NonFatal(_) => None }

  def fileOf(node: AstNode): String =
    methodOf(node).flatMap { m =>
      try { Option(m.filename) } catch { case NonFatal(_) => None }
    }.map(_.trim).filter(_.nonEmpty).getOrElse("(未知文件)")

  def funcOf(node: AstNode): String =
    methodOf(node).flatMap { m =>
      try { Option(m.name) } catch { case NonFatal(_) => None }
    }.map(_.trim).filter(_.nonEmpty).getOrElse("?")

  def locOf(node: AstNode): String = s"${fileOf(node)}:${lineOf(node)}  ${funcOf(node)}"

  def describe(node: AstNode): String =
    s"[${node.label}] ${locOf(node)}  |  ${oneLine(node.code)}"

  // 节点若作为实参出现在某个调用里（AST 父节点是 CALL），返回该调用
  def callOf(node: AstNode): Option[Call] =
    try {
      node.astParent match {
        case c: Call => Some(c)
        case _ => None
      }
    } catch { case NonFatal(_) => None }

  def endpoint(node: AstNode): String =
    locOf(node) + callOf(node).map(c => s"  调用: ${oneLine(c.code, 120)}").getOrElse("")

  val source = cpg.call
    .name("(" + sourceNames.map(java.util.regex.Pattern.quote).mkString("|") + ")")
    .argument

  // 先把 sink 调用物化，避免迭代器被 reachableByFlows 消费后，末尾清单为空
  val sinkCalls = cpg.call.name(sinkRegex).l
  val sinkArgs = sinkCalls.flatMap(_.argument.l)
  val rawFlows = sinkArgs.iterator.reachableByFlows(source).l
  // 单节点路径 = source 与 sink 是同一个节点（多为转参/自环），没有分析价值
  val flowList = rawFlows.map(_.elements.toList).filter(_.size >= 2)
  val droppedFlows = rawFlows.size - flowList.size

  val pw = new PrintWriter(outFile, "UTF-8")
  try {
    pw.println("# Joern 污点可达路径（source → sink）")
    pw.println("# 节点格式: [类型] 文件:行号  函数名  |  代码片段")
    pw.println("# 注意: 流上的节点可能是变量、常量、参数，不一定是函数调用；函数名表示该节点所在的函数。")
    pw.println(s"# sink 名单来源: ${if (extraSinks.nonEmpty) sinksPath else "默认名单"}")
    pw.println(s"# sink 名单(${sinkNames.size}): ${sinkNames.mkString(", ")}")
    pw.println(s"# 污点可达路径数: ${flowList.size}")
    if (droppedFlows > 0)
      pw.println(s"# 已过滤单节点自环路径: $droppedFlows 条")

    val filesSeen = scala.collection.mutable.Set[String]()
    val funcsSeen = scala.collection.mutable.Set[String]()

    flowList.zipWithIndex.foreach { case (elements, i) =>
      elements.foreach { e =>
        val f = fileOf(e)
        if (!f.startsWith("(")) filesSeen += f
        val fn = funcOf(e)
        if (fn != "?") funcsSeen += s"$f :: $fn"
      }
      val head = elements.headOption.map(endpoint).getOrElse("?")
      val last = elements.lastOption.map(endpoint).getOrElse("?")
      pw.println("")
      pw.println(s"## flow ${i + 1}（${elements.size} 个节点）  从 $head  到 $last")
      elements.zipWithIndex.foreach { case (e, j) =>
        pw.println(s"  ${j + 1}. ${describe(e)}")
      }
    }

    pw.println("")
    pw.println(s"# 汇总: 路径 ${flowList.size} 条，涉及文件 ${filesSeen.size} 个，函数 ${funcsSeen.size} 个")
    filesSeen.toList.sorted.foreach(f => pw.println(s"#   文件: $f"))

    pw.println("")
    pw.println("# 命中的 sink 调用清单（文件:行号  函数  |  代码）")
    sinkCalls.distinct.foreach { c =>
      pw.println(s"  - ${locOf(c)}  |  ${oneLine(c.code)}")
    }
  } finally {
    pw.close()
  }

  println(s"污点分析完成，结果: $outFile（路径数 ${flowList.size}，过滤单节点 $droppedFlows 条，sink 名单 ${sinkNames.size} 个）")
}

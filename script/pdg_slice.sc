import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

@main def main(
  cpgPath: String,
  sourceFile: String,
  sourceLine: Int,
  sinkFile: String,
  sinkLine: Int
) = {
  require(sourceFile.nonEmpty, "sourceFile cannot be empty")
  require(sourceLine > 0, s"sourceLine must be positive: $sourceLine")
  require(sinkFile.nonEmpty, "sinkFile cannot be empty")
  require(sinkLine > 0, s"sinkLine must be positive: $sinkLine")

  val projectName = s"joern-trace-${System.currentTimeMillis()}"

  val imported = importCpg(cpgPath, projectName)
  if (imported.isEmpty) {
    throw new RuntimeException(s"Failed to import CPG: $cpgPath")
  }

  try {
    /*
     * 지정된 파일과 라인에 존재하는 Source CFG 노드만 선택한다.
     *
     * CPG 내부 파일명이 전체 경로로 저장된 경우도 처리하기 위해
     * nameExact 대신 endsWith를 사용한다.
     */
    val sourceNodes =
      cpg.astNode
        .filter(_.lineNumber.contains(sourceLine))
        .filter { node =>
          node.file.name.headOption.exists(_.endsWith(sourceFile))
        }
        .isCfgNode
        .l

    /*
     * 지정된 파일과 라인에 존재하는 Sink CFG 노드만 선택한다.
     */
    val sinkNodes =
      cpg.astNode
        .filter(_.lineNumber.contains(sinkLine))
        .filter { node =>
          node.file.name.headOption.exists(_.endsWith(sinkFile))
        }
        .isCfgNode
        .l

    if (sourceNodes.isEmpty) {
      val sourceLineCandidates =
        cpg.astNode
          .filter(_.lineNumber.contains(sourceLine))
          .map { node =>
            (
              node.file.name.headOption.getOrElse("<unknown>"),
              node.label,
              node.code
            )
          }
          .distinct
          .l

      println()
      println("=== Source Line Candidates ===")

      if (sourceLineCandidates.isEmpty) {
        println(s"No AST nodes found at line $sourceLine")
      } else {
        sourceLineCandidates.foreach { case (file, label, code) =>
          println(s"$file | $label | $code")
        }
      }

      throw new RuntimeException(
        s"No CFG nodes found at source: $sourceFile:$sourceLine"
      )
    }

    if (sinkNodes.isEmpty) {
      val sinkLineCandidates =
        cpg.astNode
          .filter(_.lineNumber.contains(sinkLine))
          .map { node =>
            (
              node.file.name.headOption.getOrElse("<unknown>"),
              node.label,
              node.code
            )
          }
          .distinct
          .l

      println()
      println("=== Sink Line Candidates ===")

      if (sinkLineCandidates.isEmpty) {
        println(s"No AST nodes found at line $sinkLine")
      } else {
        sinkLineCandidates.foreach { case (file, label, code) =>
          println(s"$file | $label | $code")
        }
      }

      throw new RuntimeException(
        s"No CFG nodes found at sink: $sinkFile:$sinkLine"
      )
    }

    println()
    println("=== Analysis Target ===")
    println(s"CPG         : $cpgPath")
    println(
      s"Source      : $sourceFile:$sourceLine " +
        s"(${sourceNodes.size} CFG node(s))"
    )
    println(
      s"Sink        : $sinkFile:$sinkLine " +
        s"(${sinkNodes.size} CFG node(s))"
    )

    /*
     * 1. Source -> Sink 데이터 흐름 탐색
     */
    val flows =
      sinkNodes.iterator
        .reachableByFlows(sourceNodes)
        .l

    val uniqueFlows =
      flows
        .map(_.resultPairs())
        .distinct

    println()

    /*
     * Source -> Sink 데이터 흐름 출력
     */
    if (uniqueFlows.isEmpty) {
      println("=== Source-to-Sink Trace ===")
      println("No data-flow path found.")
    } else {
      uniqueFlows.zipWithIndex.foreach { case (flow, flowIndex) =>
        val title =
          if (uniqueFlows.size == 1) {
            "=== Source-to-Sink Trace ==="
          } else {
            s"=== Source-to-Sink Trace ${flowIndex + 1}/${uniqueFlows.size} ==="
          }

        println(title)
        println()

        flow.zipWithIndex.foreach {
          case ((code, line), stepIndex) =>
            println(
              s"[$stepIndex] line=${line.getOrElse(-1)} | $code"
            )

            if (stepIndex < flow.size - 1) {
              println("        ↓")
            }
        }

        if (flowIndex < uniqueFlows.size - 1) {
          println()
        }
      }
    }

    /*
     * Source -> Sink 데이터 흐름이 존재하는 경우에만
     * DDG + CDG backward slice를 수행한다.
     */
    if (flows.nonEmpty) {

      /*
       * 2. Source -> Sink 데이터 흐름 노드 추출
       */
      val flowNodes =
        flows
          .flatMap(_.elements)
          .iterator
          .isCfgNode
          .dedup
          .l

      /*
       * 3. 데이터 흐름 노드에 영향을 주는 DDG predecessor 추가
       */
      val dataNodes =
        (
          flowNodes ++
            flowNodes.iterator
              .repeat(_.ddgIn)(
                _.maxDepth(20)
                  .emit
              )
              .l
        ).distinct

      /*
       * 4. 데이터 노드를 제어하는 CDG predicate 추출
       */
      val controlNodes =
        dataNodes.iterator
          .controlledBy
          .dedup
          .l

      /*
       * 5. 제어조건에 영향을 주는 DDG predecessor 추가
       */
      val controlInputs =
        (
          controlNodes ++
            controlNodes.iterator
              .repeat(_.ddgIn)(
                _.maxDepth(20)
                  .emit
              )
              .l
        ).distinct

      /*
       * 6. 전체 PDG backward slice 결합
       */
      val allInfluences =
        (
          dataNodes ++
            controlNodes ++
            controlInputs
        ).distinct

      /*
       * AST 상에서 slice 노드를 감싸는 제어 구조 추가
       */
      val enclosingControls =
        allInfluences.iterator
          .inAst
          .isControlStructure
          .dedup
          .l

      val finalNodes =
        (
          allInfluences ++
            enclosingControls
        ).distinct

      /*
       * 7. DDG + CDG backward slice 출력
       */
      println()
      println("=== DDG + CDG Backward Slice ===")
      println()

      finalNodes
        .map { node =>
          (
            node.file.name.headOption.getOrElse("<unknown>"),
            node.lineNumber.getOrElse(-1),
            node.columnNumber.getOrElse(-1),
            node.code
          )
        }
        .filter { case (_, line, _, _) =>
          line >= 0
        }
        .distinct
        .sortBy { case (file, line, column, _) =>
          (file, line, column)
        }
        .foreach { case (file, line, column, code) =>
          println(
            s"$file | line=$line, col=$column | $code"
          )
        }

      println()
      println("=== PDG Slice Summary ===")
      println(s"Flow nodes        : ${flowNodes.size}")
      println(s"Data nodes        : ${dataNodes.size}")
      println(s"Control nodes     : ${controlNodes.size}")
      println(s"Control DDG nodes : ${controlInputs.size}")
      println(s"AST controls      : ${enclosingControls.size}")
      println(s"Final slice nodes : ${finalNodes.size}")
    }

    println()
    println("=== Summary ===")
    println(s"Raw paths    : ${flows.size}")
    println(s"Unique traces: ${uniqueFlows.size}")
  } finally {
    delete(projectName)
  }
}
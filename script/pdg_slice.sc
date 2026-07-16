import io.joern.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import java.util.UUID

import scala.collection.mutable


/*
 * DDG backward 탐색 최대 깊이
 */
val SliceDepth = 8


/*
 * CPG 노드 ID를 기준으로 중복을 제거한다.
 *
 * 입력 순서는 유지한다.
 */
def distinctById(
  nodes: IterableOnce[CfgNode]
): List[CfgNode] = {
  val seen = mutable.HashSet.empty[Long]

  nodes.iterator
    .filter { node =>
      seen.add(node.id)
    }
    .toList
}


/*
 * DDG predecessor를 BFS 방식으로 역추적한다.
 *
 * 기존 repeat(_.ddgIn)는 동일 노드를 여러 경로에서 반복해서
 * 탐색할 수 있다. 이 함수는 visited 집합을 사용하여 각 노드를
 * 최대 한 번만 확장한다.
 *
 * startNodes도 결과에 포함된다.
 */
def backwardDdg(
  startNodes: List[CfgNode],
  maxDepth: Int
): List[CfgNode] = {
  val visited =
    mutable.LinkedHashMap.empty[Long, CfgNode]

  var frontier =
    distinctById(startNodes)

  var currentDepth = 0

  frontier.foreach { node =>
    visited.update(node.id, node)
  }

  while (
    frontier.nonEmpty &&
    currentDepth < maxDepth
  ) {
    /*
     * 현재 frontier의 DDG predecessor를 한 단계 탐색한다.
     */
    val predecessors =
      frontier.iterator
        .ddgIn
        .l

    /*
     * 이미 방문한 노드는 다음 frontier에서 제외한다.
     */
    val nextFrontier =
      distinctById(
        predecessors.filterNot { node =>
          visited.contains(node.id)
        }
      )

    nextFrontier.foreach { node =>
      visited.update(node.id, node)
    }

    frontier = nextFrontier
    currentDepth += 1
  }

  visited.values.toList
}


@main def main(
  cpgPath: String,
  sourceFile: String,
  sourceLine: Int,
  sinkFile: String,
  sinkLine: Int
) = {
  require(
    sourceFile.nonEmpty,
    "sourceFile cannot be empty"
  )

  require(
    sourceLine > 0,
    s"sourceLine must be positive: $sourceLine"
  )

  require(
    sinkFile.nonEmpty,
    "sinkFile cannot be empty"
  )

  require(
    sinkLine > 0,
    s"sinkLine must be positive: $sinkLine"
  )

  val projectName =
    s"joern-trace-${UUID.randomUUID().toString}"

  val imported =
    importCpg(cpgPath, projectName)

  if (imported.isEmpty) {
    throw new RuntimeException(
      s"Failed to import CPG: $cpgPath"
    )
  }

  try {
    /*
     * 지정된 파일과 라인에 존재하는 Source CFG 노드를 선택한다.
     *
     * 한 줄에 CALL, IDENTIFIER, 대입문 등 여러 CFG 노드가 있으면
     * 기존과 동일하게 모두 Source 후보로 사용한다.
     *
     * CPG 내부 파일명이 전체 상대경로로 저장될 수 있으므로
     * endsWith로 파일명을 비교한다.
     */
    val sourceNodes =
      cpg.astNode
        .filter(_.lineNumber.contains(sourceLine))
        .filter { node =>
          node.file.name.headOption.exists(
            _.endsWith(sourceFile)
          )
        }
        .isCfgNode
        .dedup
        .l

    /*
     * 지정된 파일과 라인에 존재하는 Sink CFG 노드를 선택한다.
     */
    val sinkNodes =
      cpg.astNode
        .filter(_.lineNumber.contains(sinkLine))
        .filter { node =>
          node.file.name.headOption.exists(
            _.endsWith(sinkFile)
          )
        }
        .isCfgNode
        .dedup
        .l

    /*
     * Source 노드를 찾지 못한 경우 해당 라인의 AST 후보를 출력한다.
     */
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
        println(
          s"No AST nodes found at line $sourceLine"
        )
      } else {
        sourceLineCandidates.foreach {
          case (file, label, code) =>
            println(
              s"$file | $label | $code"
            )
        }
      }

      throw new RuntimeException(
        s"No CFG nodes found at source: " +
          s"$sourceFile:$sourceLine"
      )
    }

    /*
     * Sink 노드를 찾지 못한 경우 해당 라인의 AST 후보를 출력한다.
     */
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
        println(
          s"No AST nodes found at line $sinkLine"
        )
      } else {
        sinkLineCandidates.foreach {
          case (file, label, code) =>
            println(
              s"$file | $label | $code"
            )
        }
      }

      throw new RuntimeException(
        s"No CFG nodes found at sink: " +
          s"$sinkFile:$sinkLine"
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
    println(s"Slice depth : $SliceDepth")

    /*
     * 1. Source -> Sink 데이터 흐름 탐색
     */
    println()
    println("=== Source-to-Sink Search Started ===")

    val flowSearchStartedAt =
      System.nanoTime()

    val rawFlows =
      sinkNodes.iterator
        .reachableByFlows(sourceNodes)
        .l

    val flowSearchSeconds =
      (
        System.nanoTime() -
          flowSearchStartedAt
      ) / 1_000_000_000.0

    /*
     * 같은 resultPairs를 가진 Flow는 하나만 유지한다.
     *
     * 대표 Flow 객체를 유지하므로 이후 flow.elements에서
     * 동일한 경로 노드를 반복 처리하지 않는다.
     */
    val uniqueFlowObjects =
      rawFlows.distinctBy(
        _.resultPairs()
      )

    val uniqueFlows =
      uniqueFlowObjects.map(
        _.resultPairs()
      )

    println(
      f"Source-to-Sink search completed: " +
        f"$flowSearchSeconds%.3f seconds"
    )

    println()

    /*
     * Source -> Sink 데이터 흐름 출력
     */
    if (uniqueFlows.isEmpty) {
      println("=== Source-to-Sink Trace ===")
      println("No data-flow path found.")
    } else {
      uniqueFlows.zipWithIndex.foreach {
        case (flow, flowIndex) =>
          val title =
            if (uniqueFlows.size == 1) {
              "=== Source-to-Sink Trace ==="
            } else {
              s"=== Source-to-Sink Trace " +
                s"${flowIndex + 1}/${uniqueFlows.size} ==="
            }

          println(title)
          println()

          flow.zipWithIndex.foreach {
            case ((code, line), stepIndex) =>
              println(
                s"[$stepIndex] " +
                  s"line=${line.getOrElse(-1)} | $code"
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
    if (uniqueFlowObjects.nonEmpty) {
      println()
      println(
        s"=== DDG + CDG Backward Slice Started " +
          s"(depth=$SliceDepth) ==="
      )

      val sliceStartedAt =
        System.nanoTime()

      /*
       * 2. 중복 제거된 Source -> Sink Flow의 CFG 노드를 추출한다.
       */
      val flowNodes =
        uniqueFlowObjects
          .flatMap(_.elements)
          .iterator
          .isCfgNode
          .dedup
          .l

      /*
       * 3. Flow 노드에 영향을 주는 DDG predecessor를 추가한다.
       *
       * 각 노드는 한 번만 확장하며 최대 깊이는 8이다.
       */
      val dataNodes =
        backwardDdg(
          flowNodes,
          SliceDepth
        )

      /*
       * 4. 데이터 노드를 제어하는 CDG predicate를 추출한다.
       */
      val controlNodes =
        dataNodes.iterator
          .controlledBy
          .dedup
          .l

      /*
       * 5. 제어조건에 영향을 주는 DDG predecessor를 추가한다.
       *
       * controlNodes 자체도 결과에 포함한다.
       */
      val controlInputs =
        backwardDdg(
          controlNodes,
          SliceDepth
        )

      /*
       * 6. 데이터 의존성과 제어 의존성을 결합한다.
       */
      val allInfluences =
        distinctById(
          dataNodes ++
            controlNodes ++
            controlInputs
        )

      /*
       * AST 상에서 slice 노드를 감싸는 제어 구조를 추가한다.
       */
      val enclosingControls =
        allInfluences.iterator
          .inAst
          .isControlStructure
          .dedup
          .l

      val finalNodes =
        distinctById(
          allInfluences ++
            enclosingControls
        )

      val sliceSeconds =
        (
          System.nanoTime() -
            sliceStartedAt
        ) / 1_000_000_000.0

      /*
       * 7. DDG + CDG backward slice 출력
       */
      println()
      println("=== DDG + CDG Backward Slice ===")
      println()

      finalNodes
        .map { node =>
          (
            node.file.name
              .headOption
              .getOrElse("<unknown>"),
            node.lineNumber
              .getOrElse(-1),
            node.columnNumber
              .getOrElse(-1),
            node.code
          )
        }
        .filter {
          case (_, line, _, _) =>
            line >= 0
        }
        .distinct
        .sortBy {
          case (file, line, column, _) =>
            (
              file,
              line,
              column
            )
        }
        .foreach {
          case (file, line, column, code) =>
            println(
              s"$file | " +
                s"line=$line, col=$column | $code"
            )
        }

      println()
      println("=== PDG Slice Summary ===")
      println(s"Slice depth       : $SliceDepth")
      println(s"Flow nodes        : ${flowNodes.size}")
      println(s"Data nodes        : ${dataNodes.size}")
      println(s"Control nodes     : ${controlNodes.size}")
      println(
        s"Control DDG nodes : ${controlInputs.size}"
      )
      println(
        s"AST controls      : ${enclosingControls.size}"
      )
      println(
        s"Final slice nodes : ${finalNodes.size}"
      )
      println(
        f"Slice time        : $sliceSeconds%.3f seconds"
      )
    }

    println()
    println("=== Summary ===")
    println(s"Raw paths    : ${rawFlows.size}")
    println(s"Unique traces: ${uniqueFlows.size}")
    println(
      f"Flow time    : $flowSearchSeconds%.3f seconds"
    )
  } finally {
    delete(projectName)
  }
}

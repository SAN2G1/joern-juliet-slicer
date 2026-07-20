#!/usr/bin/env python3
"""Run PDG slicing for every CPG in a CWE CPG directory.

Example:
    python3 batch_slicer.py output/CPG/cwe15_cpg
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_XML_DIR = PROJECT_ROOT / "output" / "filtered_source_sink_dataset"
DEFAULT_SCRIPT = PROJECT_ROOT / "script" / "run_pdg_slice.sh"


@dataclass(frozen=True)
class Flow:
    """One source-to-sink flow extracted from the XML."""

    flow_index: str
    flow_type: str
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int


@dataclass(frozen=True)
class CpgTaskResult:
    """Result of slicing one CPG across all of its flows."""

    cpg_path: Path
    testcase_index: str
    flow_results: list[str]
    failed: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "For each CPG in a CWE CPG folder, read the testcase flows from XML, "
            "run the PDG slicer once per flow, and save one TXT result per CPG."
        )
    )
    parser.add_argument(
        "cpg_dir",
        type=Path,
        help="Directory containing files such as cwe15-2-cpg-resolved.bin.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing TXT files. By default, existing results are skipped.",
    )
    parser.add_argument(
        "--parallel",
        dest="parallel",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help=(
            "Number of CPG files to process in parallel "
            "(default: min(4, CPU count))."
        ),
    )
    return parser.parse_args()


def cwe_number_from_name(name: str) -> str:
    match = re.search(r"cwe[_-]?(\d+)", name, flags=re.IGNORECASE)
    if not match:
        raise ValueError(f"Could not determine CWE number from: {name}")
    return match.group(1)


def infer_xml_path(cwe_number: str) -> Path:
    return DEFAULT_XML_DIR / f"cwe{cwe_number}_source_sink_classified.xml"


def normalize_output_dir_name(name: str) -> str:
    normalized = re.sub(r"_cpg(?=_|$)", "cpg", name, flags=re.IGNORECASE)
    return normalized


def parse_cpg_name(path: Path) -> tuple[str, str]:
    match = re.fullmatch(
        r"(cwe\d+)-(\d+)-cpg-resolved\.bin",
        path.name,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError(
            f"Unexpected CPG file name: {path.name} "
            "(expected cwe<NUMBER>-<TESTCASE>-cpg-resolved.bin)"
        )
    return match.group(1).lower(), match.group(2)


def read_flows_by_testcase(xml_path: Path) -> dict[str, list[Flow]]:
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid XML file {xml_path}: {error}") from error

    flows_by_testcase: dict[str, list[Flow]] = {}
    for testcase in root.findall("testcase"):
        testcase_index = testcase.get("testcase_index")
        if not testcase_index:
            raise ValueError("A testcase is missing testcase_index")

        flows: list[Flow] = []
        for flow_element in testcase.findall("flow"):
            flow_index = flow_element.get("flow_index", "?")
            flow_type = flow_element.get("type", "?")
            source_node = next(
                (node for node in flow_element if node.get("role") == "source"),
                None,
            )
            sink_node = next(
                (node for node in flow_element if node.get("role") == "sink"),
                None,
            )
            if source_node is None or sink_node is None:
                raise ValueError(
                    f"Testcase {testcase_index}, flow {flow_index} is missing a "
                    "source or sink node"
                )

            source_file = source_node.get("file")
            sink_file = sink_node.get("file")
            source_line = source_node.get("line")
            sink_line = sink_node.get("line")
            if not source_file or not sink_file or not source_line or not sink_line:
                raise ValueError(
                    f"Testcase {testcase_index}, flow {flow_index} has incomplete "
                    "file/line information"
                )

            flows.append(
                Flow(
                    flow_index=flow_index,
                    flow_type=flow_type,
                    source_file=source_file,
                    source_line=int(source_line),
                    sink_file=sink_file,
                    sink_line=int(sink_line),
                )
            )

        if not flows:
            raise ValueError(f"Testcase {testcase_index} has no flows")
        flows_by_testcase[testcase_index] = flows

    if not flows_by_testcase:
        raise ValueError(f"No testcases found in XML: {xml_path}")
    return flows_by_testcase


def sorted_cpg_files(cpg_dir: Path) -> list[Path]:
    cpg_files = [path for path in cpg_dir.iterdir() if path.is_file()]
    parsed: list[tuple[int, Path]] = []
    for path in cpg_files:
        _, testcase_index = parse_cpg_name(path)
        parsed.append((int(testcase_index), path))
    return [path for _, path in sorted(parsed)]


def result_path_for(output_dir: Path, cpg_path: Path) -> Path:
    return output_dir / f"{cpg_path.stem}.txt"


def pdg_command(script_path: Path, cpg_path: Path, flow: Flow) -> list[str]:
    return [
        str(script_path),
        str(cpg_path),
        flow.source_file,
        str(flow.source_line),
        flow.sink_file,
        str(flow.sink_line),
    ]


def show_progress(position: int, total: int, cpg_path: Path, status: str) -> None:
    """Show one updating progress line when attached to a terminal."""
    percent = position / total * 100
    message = (
        f"[{position}/{total} | {percent:5.1f}%] "
        f"{cpg_path.name}: {status}"
    )
    if sys.stdout.isatty():
        print(f"\r\033[2K{message}", end="", flush=True)
    else:
        print(message, flush=True)


def write_result(
    output_path: Path,
    cpg_path: Path,
    testcase_index: str,
    flow_results: list[str],
) -> None:
    sections = [
        f"CPG: {cpg_path}",
        f"Testcase index: {testcase_index}",
        f"Flow count: {len(flow_results)}",
        "",
    ]
    sections.extend(flow_results)
    output_path.write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")


def slice_one_cpg(
    script_path: Path,
    cpg_path: Path,
    testcase_index: str,
    flows: list[Flow],
) -> CpgTaskResult:
    flow_results: list[str] = []
    cpg_failed = False
    for flow in flows:
        command = pdg_command(script_path, cpg_path, flow)
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        header = [
            f"=== Flow {flow.flow_index} ({flow.flow_type}) ===",
            f"Command: {' '.join(command)}",
            f"Source : {flow.source_file}:{flow.source_line}",
            f"Sink   : {flow.sink_file}:{flow.sink_line}",
            f"Exit   : {completed.returncode}",
            "",
        ]
        body = completed.stdout.rstrip()
        if body:
            header.append(body)
        else:
            header.append("<no output>")
        flow_results.append("\n".join(header))

        if completed.returncode != 0:
            cpg_failed = True

    return CpgTaskResult(
        cpg_path=cpg_path,
        testcase_index=testcase_index,
        flow_results=flow_results,
        failed=cpg_failed,
    )


def run_batch(args: argparse.Namespace) -> int:
    started_at = time.perf_counter()
    cpg_dir = args.cpg_dir.expanduser().resolve()
    if not cpg_dir.is_dir():
        raise FileNotFoundError(f"CPG directory not found: {cpg_dir}")

    cwe_number = cwe_number_from_name(cpg_dir.name)
    xml_path = infer_xml_path(cwe_number).resolve()
    if not xml_path.is_file():
        raise FileNotFoundError(f"Filtered XML file not found: {xml_path}")

    script_path = DEFAULT_SCRIPT.resolve()
    if not script_path.is_file():
        raise FileNotFoundError(f"PDG slicing script not found: {script_path}")

    output_dir = PROJECT_ROOT / "output" / "slice" / normalize_output_dir_name(
        cpg_dir.name
    )
    flows_by_testcase = read_flows_by_testcase(xml_path)
    cpg_files = sorted_cpg_files(cpg_dir)
    if not cpg_files:
        raise ValueError(f"No CPG files found in directory: {cpg_dir}")
    if args.parallel < 1:
        raise ValueError(f"--parallel must be at least 1: {args.parallel}")

    print(f"CWE               : {cwe_number}")
    print(f"CPG directory     : {cpg_dir}")
    print(f"Filtered XML      : {xml_path}")
    print(f"PDG script        : {script_path}")
    print(f"Result output dir : {output_dir}")
    print(f"CPG files         : {len(cpg_files)}")
    print(f"Parallel CPGs     : {args.parallel}")

    output_dir.mkdir(parents=True, exist_ok=True)

    saved = 0
    skipped = 0
    failed = 0
    total = len(cpg_files)
    future_to_cpg: dict[object, Path] = {}
    processed_count = 0

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        for cpg_path in cpg_files:
            cwe_name, testcase_index = parse_cpg_name(cpg_path)
            if cwe_name != f"cwe{cwe_number}":
                raise ValueError(
                    f"CWE mismatch: directory suggests cwe{cwe_number}, but file is {cpg_path.name}"
                )

            flows = flows_by_testcase.get(testcase_index)
            if flows is None:
                raise ValueError(
                    f"Testcase index {testcase_index} from {cpg_path.name} "
                    f"was not found in {xml_path.name}"
                )

            output_path = result_path_for(output_dir, cpg_path)
            if output_path.exists() and not args.force:
                skipped += 1
                processed_count += 1
                show_progress(
                    processed_count,
                    total,
                    cpg_path,
                    f"skipped -> {output_path.name} (already exists)",
                )
                continue

            future = executor.submit(
                slice_one_cpg,
                script_path,
                cpg_path,
                testcase_index,
                flows,
            )
            future_to_cpg[future] = cpg_path

        for future in as_completed(future_to_cpg):
            result = future.result()
            output_path = result_path_for(output_dir, result.cpg_path)
            write_result(
                output_path,
                result.cpg_path,
                result.testcase_index,
                result.flow_results,
            )

            processed_count += 1
            if result.failed:
                failed += 1
                show_progress(
                    processed_count,
                    total,
                    result.cpg_path,
                    f"saved with failures -> {output_path.name}",
                )
            else:
                saved += 1
                show_progress(
                    processed_count,
                    total,
                    result.cpg_path,
                    f"saved -> {output_path.name}",
                )

    if sys.stdout.isatty():
        print()
    print()
    elapsed_seconds = time.perf_counter() - started_at
    print(f"Complete: {saved} saved, {skipped} skipped, {failed} with failures")
    print(f"Total time: {elapsed_seconds:.3f} seconds")
    print(f"Results : {output_dir}")
    return 1 if failed else 0


def main() -> int:
    args = parse_args()
    try:
        return run_batch(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

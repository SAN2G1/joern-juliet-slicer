#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path


WARNING_CODE = "WARNING_NOT_FOUND"
VALID_ROLES = {"source", "sink"}
VALID_SAFETIES = {"bad", "good"}
ORIGIN_TO_SAFETY = {
    "comment_flaw": "bad",
    "comment_fix": "good",
}
FLOW_EXPECTATIONS = {
    "b2b": {"source": "bad", "sink": "bad"},
    "b2g": {"source": "bad", "sink": "good"},
    "b2g1": {"source": "bad", "sink": "good"},
    "b2g2": {"source": "bad", "sink": "good"},
    "g2b": {"source": "good", "sink": "bad"},
    "g2b1": {"source": "good", "sink": "bad"},
    "g2b2": {"source": "good", "sink": "bad"},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Filter Java SARD source/sink XMLs and keep only valid flows."
        )
    )
    parser.add_argument(
        "input_path",
        help="Input XML file or directory containing XML files.",
    )
    parser.add_argument(
        "--output-dir",
        default="output/filtered_source_sink_dataset",
        help=(
            "Output directory relative to this script directory "
            "(default: output/filtered_source_sink_dataset)."
        ),
    )
    parser.add_argument(
        "--verbose-summary",
        action="store_true",
        help="Print detailed reasons for skipped flows and rejected nodes.",
    )
    parser.add_argument(
        "--show-summary",
        action="store_true",
        help="Print the final overall summary after processing all XML files.",
    )
    return parser.parse_args()


def iter_xml_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path] if input_path.suffix.lower() == ".xml" else []
    if input_path.is_dir():
        return sorted(
            path for path in input_path.iterdir() if path.suffix.lower() == ".xml"
        )
    return []


def flow_expectation(flow_type: str | None) -> dict[str, str] | None:
    if not flow_type:
        return None
    return FLOW_EXPECTATIONS.get(flow_type.strip().lower())


def line_is_positive_int(value: str | None) -> bool:
    if value is None or not value.isdigit():
        return False
    return int(value) > 0


def code_is_invalid(code: str | None) -> bool:
    code_text = (code or "").strip()
    return (
        not code_text
        or code_text == WARNING_CODE
        or code_text.startswith("/*")
    )


def collect_node_issues(
    node: ET.Element,
    expected: dict[str, str],
) -> set[str]:
    role = node.get("role")
    safety = node.get("safety")
    origin = node.get("origin")
    code = node.get("code")
    issues: set[str] = set()

    if code_is_invalid(code):
        issues.add("invalid_code")
    if role not in VALID_ROLES:
        issues.add("bad_role")
    if safety not in VALID_SAFETIES:
        issues.add("bad_safety")
    if not line_is_positive_int(node.get("line")):
        issues.add("bad_line")
    if not node.get("function"):
        issues.add("missing_function")
    if not node.get("file"):
        issues.add("missing_file")
    if origin not in ORIGIN_TO_SAFETY:
        issues.add("bad_origin")
    elif safety in VALID_SAFETIES and ORIGIN_TO_SAFETY[origin] != safety:
        issues.add("origin_safety_mismatch")
    if role in VALID_ROLES and safety in VALID_SAFETIES:
        if expected.get(role) != safety:
            issues.add("flow_safety_mismatch")

    return issues


def build_file_index(testcase: ET.Element) -> dict[str, ET.Element]:
    index: dict[str, ET.Element] = {}
    for file_elem in testcase.findall("file"):
        path = file_elem.get("path")
        if path:
            index[path] = file_elem
    return index


def comment_key(node: ET.Element) -> tuple[str | None, str | None, str | None]:
    return (
        node.get("function"),
        node.get("line"),
        node.tag,
    )


def flow_key(node: ET.Element) -> tuple[str | None, str | None, str | None]:
    origin = node.get("origin")
    if origin == "comment_flaw":
        comment_tag = "comment_flaw"
    elif origin == "comment_fix":
        comment_tag = "comment_fix"
    else:
        comment_tag = None
    return (
        node.get("function"),
        node.get("line"),
        comment_tag,
    )


def filter_xml(xml_path: Path, output_dir: Path) -> tuple[Path, Counter]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    stats = Counter()
    new_root = ET.Element(root.tag, root.attrib)

    for testcase in root.findall("testcase"):
        stats["testcases_total"] += 1
        file_index = build_file_index(testcase)
        valid_flows: list[ET.Element] = []
        required_comments: dict[
            str, set[tuple[str | None, str | None, str | None]]
        ] = defaultdict(set)

        for flow in testcase.findall("flow"):
            stats["flows_total"] += 1
            expected = flow_expectation(flow.get("type"))
            if expected is None:
                stats["flows_dropped_unknown_type"] += 1
                continue

            valid_nodes = []
            for node in flow:
                issues = collect_node_issues(node, expected)
                for issue in issues:
                    stats[f"flow_nodes_with_{issue}"] += 1
                if not issues:
                    valid_nodes.append(node)

            sources = [node for node in valid_nodes if node.get("role") == "source"]
            sinks = [node for node in valid_nodes if node.get("role") == "sink"]

            if len(sources) != 1 or len(sinks) != 1:
                stats["flows_dropped_invalid_endpoints"] += 1
                if len(sources) == 0:
                    stats["flows_dropped_missing_source"] += 1
                elif len(sources) > 1:
                    stats["flows_dropped_multiple_sources"] += 1
                if len(sinks) == 0:
                    stats["flows_dropped_missing_sink"] += 1
                elif len(sinks) > 1:
                    stats["flows_dropped_multiple_sinks"] += 1
                continue

            source_node = sources[0]
            sink_node = sinks[0]

            if (
                source_node.get("file") not in file_index
                or sink_node.get("file") not in file_index
            ):
                stats["flows_dropped_missing_file_entry"] += 1
                continue

            new_flow = ET.Element(flow.tag, flow.attrib)
            new_flow.append(copy.deepcopy(source_node))
            new_flow.append(copy.deepcopy(sink_node))
            valid_flows.append(new_flow)

            required_comments[source_node.get("file")].add(flow_key(source_node))
            required_comments[sink_node.get("file")].add(flow_key(sink_node))
            stats["flows_kept"] += 1

        if not valid_flows:
            stats["testcases_dropped"] += 1
            continue

        new_testcase = ET.Element(testcase.tag, testcase.attrib)

        for file_elem in testcase.findall("file"):
            file_path = file_elem.get("path")
            if not file_path or file_path not in required_comments:
                continue

            new_file = ET.Element(file_elem.tag, file_elem.attrib)
            kept_comment_count = 0

            for comment in file_elem:
                if comment_key(comment) in required_comments[file_path]:
                    new_file.append(copy.deepcopy(comment))
                    kept_comment_count += 1

            if kept_comment_count > 0:
                new_testcase.append(new_file)
                stats["files_kept"] += 1

        if not new_testcase.findall("file"):
            stats["testcases_dropped_missing_comments"] += 1
            continue

        for valid_flow in valid_flows:
            new_testcase.append(valid_flow)

        new_root.append(new_testcase)
        stats["testcases_kept"] += 1

    output_path = output_dir / xml_path.name
    if not list(new_root):
        stats["files_skipped_empty"] += 1
        return output_path, stats

    output_dir.mkdir(parents=True, exist_ok=True)
    new_tree = ET.ElementTree(new_root)
    ET.indent(new_tree, space="  ")
    new_tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return output_path, stats


def print_summary(stats: Counter) -> None:
    print("=== Summary ===")
    print(f"Files processed              : 1")
    print(
        "Flows kept                   : "
        f"{stats['flows_kept']}/{stats['flows_total']}"
    )
    print(
        "Skipped: unknown flow type   : "
        f"{stats['flows_dropped_unknown_type']}"
    )
    print(
        "Skipped: missing file entry  : "
        f"{stats['flows_dropped_missing_file_entry']}"
    )
    print(
        "Skipped: no valid source/sink: "
        f"{stats['flows_dropped_invalid_endpoints']}"
    )


def print_details(stats: Counter) -> None:
    print()
    print("=== Details ===")
    print(
        "Missing valid source         : "
        f"{stats['flows_dropped_missing_source']}"
    )
    print(
        "Multiple valid sources       : "
        f"{stats['flows_dropped_multiple_sources']}"
    )
    print(
        "Missing valid sink           : "
        f"{stats['flows_dropped_missing_sink']}"
    )
    print(
        "Multiple valid sinks         : "
        f"{stats['flows_dropped_multiple_sinks']}"
    )
    print()
    print("Node issues found while checking flow nodes:")
    print(
        "  WARNING_NOT_FOUND          : "
        f"{stats['flow_nodes_with_warning_or_empty_code']}"
    )
    print(
        "  Origin/safety mismatch     : "
        f"{stats['flow_nodes_with_origin_safety_mismatch']}"
    )
    print(
        "  Missing or invalid role    : "
        f"{stats['flow_nodes_with_bad_role']}"
    )


def main() -> int:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    input_path = Path(args.input_path).resolve()
    output_dir = (script_dir / args.output_dir).resolve()

    xml_files = iter_xml_files(input_path)
    if not xml_files:
        print(f"No XML files found: {input_path}", file=sys.stderr)
        return 1

    file_totals = Counter()
    for index, xml_file in enumerate(xml_files):
        if index > 0:
            print()
            if args.show_summary or args.verbose_summary:
                print()
        try:
            output_path, stats = filter_xml(xml_file, output_dir)
        except ET.ParseError as exc:
            print(f"[FAIL] {xml_file}: XML parse error: {exc}", file=sys.stderr)
            file_totals["fail"] += 1
            continue

        if stats["files_skipped_empty"]:
            print(
                f"[SKIP] {xml_file.name} | no valid flows, "
                f"output not written"
            )
            file_totals["skip"] += 1
        else:
            print(
                f"[OK] {xml_file.name} -> {output_path} | "
                f"flows kept={stats['flows_kept']}/{stats['flows_total']}, "
                f"testcases kept={stats['testcases_kept']}/{stats['testcases_total']}"
            )
            file_totals["ok"] += 1

        if args.show_summary or args.verbose_summary:
            print()
            print_summary(stats)
        if args.verbose_summary:
            print_details(stats)

    if input_path.is_dir():
        print()
        print("=== File Totals ===")
        print(f"XML files found : {len(xml_files)}")
        print(f"OK              : {file_totals['ok']}")
        print(f"SKIP            : {file_totals['skip']}")
        print(f"FAIL            : {file_totals['fail']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

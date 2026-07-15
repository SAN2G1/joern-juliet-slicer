#!/usr/bin/env python3
"""Build one Joern CPG for each testcase in a filtered XML file.

Example:
    python3 cpg_builder.py \
        output/filtered_source_sink_dataset/cwe15_source_sink_classified.xml
"""


from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"
REQUIRED_SETTINGS = ("JULIET_DIR", "JOERN_PARSE", "SUPPORT_JAR", "SERVLET_JAR")


@dataclass(frozen=True)
class Testcase:
    """The Java files and flows that belong to one XML testcase."""

    index: str
    java_paths: tuple[str, ...]
    flow_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build one Joern CPG for every testcase in a filtered source/sink XML."
        )
    )
    parser.add_argument("testcase_xml", help="Full path to a filtered XML file.")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help=f"Configuration file (default: {DEFAULT_ENV_FILE}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="CPG directory (default: <project>/output/cwe<NUMBER>_cpg).",
    )
    parser.add_argument(
        "--testcase-index",
        help="Build only this testcase index. By default, build every testcase.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace CPG files that already exist; otherwise they are skipped.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the XML and Java files without running joern-parse.",
    )
    return parser.parse_args()


def load_env_file(env_file: Path) -> dict[str, str]:
    """Load a simple KEY=VALUE .env file without an external dependency."""
    if not env_file.is_file():
        raise FileNotFoundError(f"Environment file not found: {env_file}")

    settings = dict(os.environ)
    for line_number, raw_line in enumerate(
        env_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            raise ValueError(f"Invalid .env entry at {env_file}:{line_number}")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        settings.setdefault(key, value)

    missing = [name for name in REQUIRED_SETTINGS if not settings.get(name)]
    if missing:
        raise ValueError(f"Missing settings in {env_file}: {', '.join(missing)}")
    return settings


def configured_path(settings: dict[str, str], name: str, env_file: Path) -> Path:
    """Resolve a configured path relative to the .env file when necessary."""
    path = Path(os.path.expandvars(os.path.expanduser(settings[name])))
    if not path.is_absolute():
        path = env_file.parent / path
    return path.resolve()


def cwe_number(xml_path: Path) -> str:
    match = re.search(r"cwe[_-]?(\d+)", xml_path.name, flags=re.IGNORECASE)
    if not match:
        raise ValueError(
            f"Could not determine the CWE number from XML name: {xml_path.name}"
        )
    return match.group(1)


def read_testcases(xml_path: Path) -> list[Testcase]:
    """Read each testcase and verify that its flows reference declared files."""
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid XML file {xml_path}: {error}") from error

    testcases: list[Testcase] = []
    seen_indexes: set[str] = set()
    for element in root.findall("testcase"):
        index = element.get("testcase_index")
        if not index:
            raise ValueError("A testcase is missing testcase_index")
        if index in seen_indexes:
            raise ValueError(f"Duplicate testcase_index: {index}")
        seen_indexes.add(index)

        java_paths = tuple(
            dict.fromkeys(
                path.replace("\\", "/")
                for file_element in element.findall("file")
                if (path := file_element.get("path"))
                and Path(path).suffix.lower() == ".java"
            )
        )
        flows = element.findall("flow")
        if not java_paths or not flows:
            raise ValueError(f"Testcase {index} has no Java files or flows")

        declared_files = {Path(path).name for path in java_paths}
        for flow in flows:
            flow_index = flow.get("flow_index", "?")
            flow_files = {node.get("file") for node in flow if node.get("file")}
            missing = flow_files - declared_files
            if missing:
                names = ", ".join(sorted(missing))
                raise ValueError(
                    f"Testcase {index}, flow {flow_index} references undeclared "
                    f"Java files: {names}"
                )

        testcases.append(Testcase(index, java_paths, len(flows)))

    if not testcases:
        raise ValueError(f"No testcases found in XML: {xml_path}")
    return testcases


def source_root_for_cwe(juliet_dir: Path, number: str) -> Path:
    """Limit searches to the CWE module when the module directory exists."""
    cwe_module = juliet_dir / f"juliet-cwe{number}"
    return cwe_module if cwe_module.is_dir() else juliet_dir


def testcase_group_prefix(java_path: str) -> str | None:
    """Extract the common prefix through a Juliet flow variant number.

    These files all produce the same prefix ending in ``_81``::

        Example_81a.java
        Example_81_base.java
        Example_81_bad.java
        Example_81_goodG2B.java

    A single-file name such as ``Example_01.java`` also has a valid prefix, but
    it only collects itself when no related suffix files exist.
    """
    stem = Path(java_path).stem
    match = re.fullmatch(r"(.+_\d+)(?:[a-z]|_[A-Za-z0-9_]+)?", stem)
    return match.group(1) if match else None


def belongs_to_testcase_group(file_name: str, prefix: str) -> bool:
    """Return whether a Java filename belongs to the given Juliet group."""
    stem = Path(file_name).stem
    if stem == prefix:
        return True
    suffix = stem.removeprefix(prefix) if stem.startswith(prefix) else ""
    return bool(
        re.fullmatch(r"[a-z]", suffix)
        or re.fullmatch(r"_[A-Za-z0-9_]+", suffix)
    )


def build_java_index(
    source_root: Path, testcases: list[Testcase]
) -> dict[str, Path]:
    """Find requested files and all members of their multi-file Juliet families."""
    wanted_names = {
        Path(java_path).name
        for testcase in testcases
        for java_path in testcase.java_paths
    }
    wanted_prefixes = {
        prefix
        for testcase in testcases
        for java_path in testcase.java_paths
        if (prefix := testcase_group_prefix(java_path))
    }
    candidates: dict[str, list[Path]] = defaultdict(list)
    for candidate in source_root.rglob("*.java"):
        belongs_to_family = any(
            belongs_to_testcase_group(candidate.name, prefix)
            for prefix in wanted_prefixes
        )
        if candidate.name in wanted_names or belongs_to_family:
            candidates[candidate.name].append(candidate)

    index: dict[str, Path] = {}
    problems: list[str] = []
    for name, matches in sorted(candidates.items()):
        if len(matches) == 1:
            index[name] = matches[0]
        else:
            locations = ", ".join(str(path) for path in matches[:3])
            problems.append(f"ambiguous: {name} -> {locations}")
    for name in sorted(wanted_names - candidates.keys()):
        problems.append(f"not found: {name}")

    if problems:
        preview = "\n  ".join(problems[:20])
        remainder = len(problems) - 20
        suffix = f"\n  ... and {remainder} more" if remainder > 0 else ""
        raise FileNotFoundError(f"Could not resolve Java files:\n  {preview}{suffix}")
    return index


def testcase_source_names(
    testcase: Testcase, java_index: dict[str, Path]
) -> list[str]:
    """Include every Java file in the testcase's Juliet filename group."""
    exact_names = {Path(path).name for path in testcase.java_paths}
    prefixes = {
        prefix
        for java_path in testcase.java_paths
        if (prefix := testcase_group_prefix(java_path))
    }
    names = []
    for name in java_index:
        in_family = any(
            belongs_to_testcase_group(name, prefix) for prefix in prefixes
        )
        if name in exact_names or in_family:
            names.append(name)
    return sorted(names)


def validate_configuration(
    juliet_dir: Path, joern_parse: Path, jars: list[Path]
) -> None:
    if not juliet_dir.is_dir():
        raise FileNotFoundError(f"JULIET_DIR is not a directory: {juliet_dir}")
    if not joern_parse.is_file():
        raise FileNotFoundError(f"JOERN_PARSE is not a file: {joern_parse}")
    for jar in jars:
        if not jar.is_file():
            raise FileNotFoundError(f"Inference JAR not found: {jar}")


def copy_testcase_sources(
    testcase: Testcase,
    java_index: dict[str, Path],
    source_root: Path,
    temp_dir: Path,
) -> list[str]:
    """Copy only this testcase's Java files, preserving their package paths."""
    source_names = testcase_source_names(testcase, java_index)
    for source_name in source_names:
        source = java_index[source_name]
        destination = temp_dir / source.relative_to(source_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return source_names


def cpg_path(output_dir: Path, number: str, testcase: Testcase) -> Path:
    return output_dir / f"cwe{number}-{testcase.index}-cpg-resolved.bin"


def joern_command(
    joern_parse: Path,
    source_dir: Path,
    output_path: Path,
    jars: list[Path],
) -> list[str]:
    return [
        str(joern_parse),
        str(source_dir),
        "--language",
        "JAVASRC",
        "--output",
        str(output_path),
        "--frontend-args",
        "--inference-jar-paths",
        ",".join(str(jar) for jar in jars),
    ]


def show_progress(position: int, total: int, testcase: Testcase, status: str) -> None:
    """Show one updating progress line when attached to a terminal."""
    percent = position / total * 100
    message = (
        f"[{position}/{total} | {percent:5.1f}%] "
        f"testcase {testcase.index}: {status}"
    )
    if sys.stdout.isatty():
        print(f"\r\033[2K{message}", end="", flush=True)
    else:
        print(message, flush=True)


def build_one_testcase(
    testcase: Testcase,
    number: str,
    output_dir: Path,
    java_index: dict[str, Path],
    source_root: Path,
    joern_parse: Path,
    jars: list[Path],
    force: bool,
    position: int,
    total: int,
) -> str:
    """Build one testcase CPG and return 'built' or 'skipped'."""
    output_path = cpg_path(output_dir, number, testcase)
    if output_path.exists() and not force:
        show_progress(position, total, testcase, "skipped (already exists)")
        return "skipped"
    if output_path.exists():
        if output_path.is_dir():
            shutil.rmtree(output_path)
        else:
            output_path.unlink()

    with tempfile.TemporaryDirectory(
        prefix=f"cwe{number}_{testcase.index}_sources_"
    ) as temp_name:
        temp_dir = Path(temp_name)
        copied_names = copy_testcase_sources(
            testcase, java_index, source_root, temp_dir
        )
        command = joern_command(joern_parse, temp_dir, output_path, jars)
        if sys.stdout.isatty() and position > 1:
            print()
        print(
            f"Testcase {testcase.index} copied sources ({len(copied_names)}): "
            + ", ".join(copied_names),
            flush=True,
        )
        show_progress(
            position,
            total,
            testcase,
            f"building ({len(copied_names)} files, {testcase.flow_count} flows)",
        )
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if completed.returncode != 0:
            log_lines = completed.stdout.strip().splitlines()
            log_tail = "\n".join(log_lines[-30:])
            raise RuntimeError(
                f"joern-parse failed for testcase {testcase.index} "
                f"(exit code {completed.returncode}).\n{log_tail}"
            )

    if not output_path.is_file():
        raise RuntimeError(f"joern-parse did not create CPG: {output_path}")
    show_progress(position, total, testcase, "saved")
    return "built"


def build_cpgs(args: argparse.Namespace) -> None:
    xml_path = Path(args.testcase_xml).expanduser().resolve()
    if not xml_path.is_file():
        raise FileNotFoundError(f"Filtered XML file not found: {xml_path}")

    env_file = args.env_file.expanduser().resolve()
    settings = load_env_file(env_file)
    number = cwe_number(xml_path)
    juliet_dir = configured_path(settings, "JULIET_DIR", env_file)
    joern_parse = configured_path(settings, "JOERN_PARSE", env_file)
    jars = [
        configured_path(settings, "SUPPORT_JAR", env_file),
        configured_path(settings, "SERVLET_JAR", env_file),
    ]
    validate_configuration(juliet_dir, joern_parse, jars)

    testcases = read_testcases(xml_path)
    if args.testcase_index is not None:
        testcases = [tc for tc in testcases if tc.index == args.testcase_index]
        if not testcases:
            raise ValueError(f"Testcase index not found: {args.testcase_index}")

    source_root = source_root_for_cwe(juliet_dir, number)
    java_index = build_java_index(source_root, testcases)
    output_dir = (
        args.output_dir.expanduser().resolve()
        if args.output_dir
        else PROJECT_ROOT / "output" / "CPG" / f"cwe{number}_cpg"
    )
    flow_count = sum(testcase.flow_count for testcase in testcases)
    java_count = len(java_index)

    print(f"CWE               : {number}")
    print(f"Filtered XML      : {xml_path}")
    print(f"Testcases         : {len(testcases)}")
    print(f"Flows             : {flow_count}")
    print(f"Unique Java files : {java_count}")
    print(f"CPG output dir    : {output_dir}")

    if args.dry_run:
        print("Dry run complete; joern-parse was not executed.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    built = 0
    skipped = 0
    total = len(testcases)
    for position, testcase in enumerate(testcases, start=1):
        result = build_one_testcase(
            testcase,
            number,
            output_dir,
            java_index,
            source_root,
            joern_parse,
            jars,
            args.force,
            position,
            total,
        )
        built += result == "built"
        skipped += result == "skipped"

    if sys.stdout.isatty():
        print()
    print(f"Complete: {built} built, {skipped} skipped -> {output_dir}")


def main() -> int:
    args = parse_args()
    try:
        build_cpgs(args)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

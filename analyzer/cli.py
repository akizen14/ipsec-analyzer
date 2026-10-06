"""Command line interface.

One command does the whole passive pipeline:

    ipsec-analyzer analyse capture.pcapng --out results/

Reads a capture, builds a session record per endpoint pair, runs the rules,
scores it, and writes the record plus both reports. Exit status is 0 on success
and 2 when a session reaches a risk level at or above ``--fail-on``, so the tool
can gate a pipeline as well as inform a person.
"""

from __future__ import annotations

from pathlib import Path

import click

from analyzer import __version__

RISK_ORDER = ["low", "medium", "high", "critical"]

SEVERITY_MARK = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "informational": "i ",
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="ipsec-analyzer")
def main() -> None:
    """Analyse IPsec VPN captures and assess their security posture."""


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--out",
    "out_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("results"),
    show_default=True,
    help="Directory for the session records and reports.",
)
@click.option("--no-reports", is_flag=True, help="Write the JSON records only.")
@click.option(
    "--fail-on",
    type=click.Choice(RISK_ORDER),
    default=None,
    help="Exit 2 if any session reaches this risk level. For use in a pipeline.",
)
@click.option("--max-packets", type=int, default=None, help="Stop after this many packets.")
@click.option("--quiet", is_flag=True, help="Print only the summary line per session.")
def analyse(
    capture: Path,
    out_dir: Path,
    no_reports: bool,
    fail_on: str | None,
    max_packets: int | None,
    quiet: bool,
) -> None:
    """Analyse a capture file and write records and reports."""
    from analyzer.ingest.pcap import read_capture
    from analyzer.record.validate import validate
    from analyzer.scoring.score import assess
    from analyzer.sessions.builder import build_sessions

    cap = read_capture(capture, max_packets=max_packets)
    click.echo(f"{capture.name}: {cap.summary()}")

    for warning in cap.warnings:
        click.secho(f"  note: {warning}", fg="yellow")

    records = build_sessions(cap)
    if not records:
        click.secho(
            "No IPsec session found. The capture needs IKE, ESP or AH traffic "
            "between a pair of hosts.",
            fg="red",
        )
        raise SystemExit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    worst_seen = -1

    for record in records:
        assess(record)
        validate(record)
        worst_seen = max(worst_seen, RISK_ORDER.index(record.score.risk_level))
        _report_one(record, out_dir, no_reports=no_reports, quiet=quiet)

    if fail_on is not None and worst_seen >= RISK_ORDER.index(fail_on):
        click.secho(
            f"\nFailing: risk {RISK_ORDER[worst_seen]} reaches the --fail-on "
            f"threshold of {fail_on}.",
            fg="red",
        )
        raise SystemExit(2)


def _report_one(record, out_dir: Path, *, no_reports: bool, quiet: bool) -> None:
    """Print one session to the terminal and write its files."""
    from reports.generator.html import write as write_report

    score = record.score
    coverage = record.coverage()
    colour = {"low": "green", "medium": "yellow", "high": "red", "critical": "red"}[
        score.risk_level
    ]

    click.echo("")
    click.secho(
        f"  {record.session_id}  {record.endpoints.initiator} -> "
        f"{record.endpoints.responder}",
        bold=True,
    )
    click.echo("    score ", nl=False)
    click.secho(f"{score.value}/100", fg=colour, bold=True, nl=False)
    click.echo("   risk ", nl=False)
    click.secho(score.risk_level.upper(), fg=colour, bold=True, nl=False)
    click.echo(
        f"   coverage {coverage.fraction:.0%}"
        f" ({coverage.determinable}/{coverage.total} attributes)"
    )

    if not quiet:
        suite = _suite_line(record)
        if suite:
            click.echo(f"    suite  {suite}")

        if record.findings:
            click.echo("    findings:")
            for finding in record.findings_sorted():
                mark = SEVERITY_MARK[finding.severity]
                conf = (
                    f" ({finding.confidence:.0%} confidence)"
                    if finding.confidence < 1.0
                    else ""
                )
                click.echo(f"      {mark} {finding.rule_id}  {finding.title}{conf}")
        else:
            click.echo("    findings: none")

        gaps = coverage.unknowns
        if gaps:
            click.echo(f"    not determinable: {len(gaps)} attribute(s), see the report")

    record_path = out_dir / f"{record.session_id}.json"
    record.dump(record_path)
    written = [record_path.name]

    if not no_reports:
        for kind in ("technical", "executive"):
            path = write_report(record, out_dir / f"{record.session_id}-{kind}.html", kind=kind)
            written.append(path.name)

    click.echo(f"    wrote  {', '.join(written)}")


def _suite_line(record) -> str:
    """The negotiated suite as one line, or a note on why it is not known."""
    ike = record.ike
    parts = []
    for attr, prefix in (
        (ike.encr, ""),
        (ike.encr_key_bits, ""),
        (ike.integ, ""),
        (ike.dh_group, "DH"),
    ):
        if attr is not None and attr.is_known:
            parts.append(f"{prefix}{attr.value}")

    if not parts:
        return "not determinable from this capture"

    version = ike.version.value if ike.version and ike.version.is_known else "IKE"
    return f"{version} {' / '.join(str(p) for p in parts)}"


@main.command()
@click.argument("record", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(["technical", "executive"]),
    default="technical",
    show_default=True,
)
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def report(record: Path, kind: str, out_path: Path | None) -> None:
    """Re-render a report from a session record that was written earlier.

    Useful after editing the rule catalogue: the record holds the evidence, so a
    report can be regenerated without re-reading the capture.
    """
    click.secho(
        "Re-rendering from a stored record is not implemented yet: it needs the "
        "record reader (SessionRecord.from_json), which lands with the dashboard "
        "in phase 6. Re-run `analyse` on the capture for now.",
        fg="yellow",
    )
    raise SystemExit(1)


@main.command()
def rules() -> None:
    """List the rule catalogue, with which rules are implemented."""
    from analyzer.rules.engine import PREDICATES, load_catalogue

    catalogue = load_catalogue()
    click.echo(f"Baseline: {', '.join(catalogue['baseline'])}\n")

    for entry in catalogue["rules"]:
        state = "  " if entry["id"] in PREDICATES else "(not implemented)"
        click.echo(f"  {entry['id']:10} {entry['severity']:14} {entry['title']} {state}")
        click.echo(f"             {entry['standard']}")

    click.echo(
        f"\n{len(PREDICATES)} of {len(catalogue['rules'])} rules implemented."
    )


@main.command()
@click.argument("capture", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def inspect(capture: Path) -> None:
    """Print what the ingest stage found, without assessing it.

    A quick check that a capture contains what it should before analysing it.
    """
    from analyzer.ingest.pcap import read_capture

    cap = read_capture(capture)
    click.echo(cap.summary())

    if cap.ike:
        click.echo(f"\nIKE: {len(cap.ike)} message(s)")
        ports = sorted({(p.sport, p.dport) for p in cap.ike})
        click.echo(f"  port pairs: {ports}")
    if cap.esp:
        spis = sorted({p.spi for p in cap.esp})
        click.echo(f"\nESP: {len(cap.esp)} packet(s) across {len(spis)} SPI(s)")
        click.echo(f"  SPIs: {', '.join(spis)}")
    if cap.ah:
        spis = sorted({p.spi for p in cap.ah})
        click.echo(f"\nAH: {len(cap.ah)} packet(s) across {len(spis)} SPI(s)")

    for warning in cap.warnings:
        click.secho(f"note: {warning}", fg="yellow")


if __name__ == "__main__":
    main()

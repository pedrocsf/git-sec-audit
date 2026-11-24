import html
import os
from string import Template

TEMPLATE_FILE_NAME = "report.html"
DATE_FORMAT = "%Y-%m-%d"
EMPTY_CELL = "-"
EMPTY_CHART = '<p class="muted">Sem dados.</p>'
SHORT_SHA_LENGTH = 10
CHART_WIDTH = 480
BAR_HEIGHT = 18
BAR_GAP = 8
LABEL_WIDTH = 150
VALUE_MARGIN = 60
PADDING = 10
LABEL_MAX_CHARS = 22
LINE_HEIGHT = 200
LINE_LEFT = 44
LINE_BOTTOM = 28
LINE_TOP = 14
MAX_CHART_ROWS = 15
DECIMALS = 1


def esc(value):
    return html.escape(str(value), quote=True)


def fmt_number(value):
    if value is None:
        return EMPTY_CELL
    return f"{value:.{DECIMALS}f}"


def fmt_date(moment):
    if moment is None:
        return EMPTY_CELL
    return moment.strftime(DATE_FORMAT)


def truncate(text):
    if len(text) <= LABEL_MAX_CHARS:
        return text
    return text[: LABEL_MAX_CHARS - 1] + "…"


def render_table(headers, rows):
    if not rows:
        return '<p class="muted">Sem dados.</p>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_horizontal_bars(items, title):
    if not items:
        return EMPTY_CHART
    items = items[:MAX_CHART_ROWS]
    peak = max(value for _, value in items) or 1
    bar_area = CHART_WIDTH - LABEL_WIDTH - VALUE_MARGIN - PADDING
    height = PADDING * 2 + len(items) * (BAR_HEIGHT + BAR_GAP)
    parts = [
        f'<svg viewBox="0 0 {CHART_WIDTH} {height}" role="img" aria-label="{esc(title)}">'
    ]
    for index, (label, value) in enumerate(items):
        y = PADDING + index * (BAR_HEIGHT + BAR_GAP)
        width = max(1, value / peak * bar_area) if value else 0
        parts.append(
            f'<text x="{LABEL_WIDTH - 6}" y="{y + BAR_HEIGHT - 5}" text-anchor="end">{esc(truncate(label))}</text>'
            f'<rect class="bar" x="{LABEL_WIDTH}" y="{y}" width="{width:.1f}" height="{BAR_HEIGHT}" rx="2"><title>{esc(label)}: {esc(value)}</title></rect>'
            f'<text x="{LABEL_WIDTH + width + 6:.1f}" y="{y + BAR_HEIGHT - 5}">{esc(value)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def render_grouped_bars(rows, title):
    if not rows:
        return EMPTY_CHART
    peak = max((v for _, a, b in rows for v in (a, b) if v is not None), default=0) or 1
    bar_area = CHART_WIDTH - LABEL_WIDTH - VALUE_MARGIN - PADDING
    row_height = BAR_HEIGHT * 2 + BAR_GAP
    height = PADDING * 2 + len(rows) * (row_height + BAR_GAP)
    parts = [
        f'<svg viewBox="0 0 {CHART_WIDTH} {height}" role="img" aria-label="{esc(title)}">'
    ]
    for index, (label, median, p90) in enumerate(rows):
        y = PADDING + index * (row_height + BAR_GAP)
        parts.append(
            f'<text x="{LABEL_WIDTH - 6}" y="{y + row_height / 2 + 4:.1f}" text-anchor="end">{esc(label)}</text>'
        )
        for offset, css, name, value in (
            (0, "bar", "mediana", median),
            (BAR_HEIGHT, "bar2", "p90", p90),
        ):
            if value is None:
                continue
            width = max(1, value / peak * bar_area) if value else 0
            parts.append(
                f'<rect class="{css}" x="{LABEL_WIDTH}" y="{y + offset}" width="{width:.1f}" height="{BAR_HEIGHT - 2}" rx="2"><title>{esc(label)} {name}: {fmt_number(value)}</title></rect>'
                f'<text x="{LABEL_WIDTH + width + 6:.1f}" y="{y + offset + BAR_HEIGHT - 6}">{name} {fmt_number(value)}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_line_chart(points, title):
    if not points:
        return EMPTY_CHART
    plot_width = CHART_WIDTH - LINE_LEFT - PADDING
    plot_height = LINE_HEIGHT - LINE_TOP - LINE_BOTTOM
    peak = max(value for _, value in points) or 1
    step = plot_width / (len(points) - 1) if len(points) > 1 else 0
    coordinates = [
        (
            LINE_LEFT + (index * step if len(points) > 1 else plot_width / 2),
            LINE_TOP + plot_height - value / peak * plot_height,
        )
        for index, (_, value) in enumerate(points)
    ]
    path = " ".join(f"{x:.1f},{y:.1f}" for x, y in coordinates)
    baseline = LINE_TOP + plot_height
    parts = [
        f'<svg viewBox="0 0 {CHART_WIDTH} {LINE_HEIGHT}" role="img" aria-label="{esc(title)}">',
        f'<line class="axis" x1="{LINE_LEFT}" y1="{baseline}" x2="{CHART_WIDTH - PADDING}" y2="{baseline}"/>',
        f'<line class="axis" x1="{LINE_LEFT}" y1="{LINE_TOP}" x2="{LINE_LEFT}" y2="{baseline}"/>',
        f'<text x="{LINE_LEFT - 4}" y="{LINE_TOP + 4}" text-anchor="end">{peak:.1f}</text>',
        f'<text x="{LINE_LEFT - 4}" y="{baseline}" text-anchor="end">0</text>',
        f'<polyline class="line" points="{path}"/>',
    ]
    for (x, y), (label, value) in zip(coordinates, points):
        parts.append(
            f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="3"><title>{esc(label)}: {value:.2f}</title></circle>'
        )
    parts.append(
        f'<text x="{coordinates[0][0]:.1f}" y="{LINE_HEIGHT - 8}" text-anchor="start">{esc(points[0][0])}</text>'
    )
    if len(points) > 1:
        parts.append(
            f'<text x="{coordinates[-1][0]:.1f}" y="{LINE_HEIGHT - 8}" text-anchor="end">{esc(points[-1][0])}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


class HtmlReportView:
    def __init__(self, templates_dir: str) -> None:
        self._templates_dir = templates_dir

    def render(self, report, output_path: str) -> str:
        template_path = os.path.join(self._templates_dir, TEMPLATE_FILE_NAME)
        with open(template_path, encoding="utf-8") as handle:
            template = Template(handle.read())
        content = template.substitute(self._placeholders(report))
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return output_path

    def _placeholders(self, report):
        exposure = report.critical_exposure_percentage
        return {
            "repository_name": esc(report.repository_name),
            "generated_at": esc(report.generated_at.isoformat()),
            "critical_exposure": EMPTY_CELL if exposure is None else f"{exposure:.2f}%",
            "mean_time_to_fix": fmt_number(report.mean_time_to_fix_days),
            "finding_count": esc(len(report.findings)),
            "patch_lag_count": esc(len(report.patch_lag_records)),
            "chart_patch_lag": render_grouped_bars(
                [
                    (s.severity.value, s.median_lag_days, s.p90_lag_days)
                    for s in report.patch_lag_summaries
                ],
                "Patch lag por severidade",
            ),
            "chart_libyears": render_line_chart(
                [(p.month.strftime(DATE_FORMAT), p.libyears) for p in report.libyears_curve],
                "Curva de libyears",
            ),
            "chart_category": render_horizontal_bars(
                list(report.findings_by_category), "Achados por categoria"
            ),
            "chart_module": render_horizontal_bars(
                list(report.findings_by_module), "Achados por módulo"
            ),
            "chart_month": render_horizontal_bars(
                list(report.findings_by_month), "Achados por mês"
            ),
            "table_patch_lag": self._patch_lag_table(report),
            "table_findings": self._findings_table(report),
            "section_authors": self._authors_section(report),
            "warnings_block": self._warnings_block(report),
        }

    def _patch_lag_table(self, report):
        headers = (
            "CVE/advisory", "Pacote", "Severidade", "Versão vulnerável",
            "Versão corrigida", "Dias de lag", "Commit",
        )
        rows = [
            (
                r.advisory.display_id,
                r.advisory.package,
                r.severity.value,
                r.vulnerable_version,
                r.fixed_version or EMPTY_CELL,
                fmt_number(r.lag_days),
                (r.fix_commit_sha or EMPTY_CELL)[:SHORT_SHA_LENGTH],
            )
            for r in report.patch_lag_records
        ]
        return render_table(headers, rows)

    def _findings_table(self, report):
        visible_names = {a.author_label for a in report.author_rankings}
        headers = (
            "Tipo", "Regra", "Categoria", "Severidade", "Arquivo", "Módulo",
            "Entrada", "Saída", "Dias", "Autor",
        )
        rows = [
            (
                f.kind.value,
                f.rule_id,
                f.category,
                f.severity.value,
                f.file_path,
                f.module,
                fmt_date(f.introduced_at),
                fmt_date(f.fixed_at),
                fmt_number(f.lifetime_days(report.generated_at)),
                f.introduced_by.name if f.introduced_by and f.introduced_by.name in visible_names else EMPTY_CELL,
            )
            for f in report.findings
        ]
        return render_table(headers, rows)

    def _authors_section(self, report):
        if not report.author_rankings:
            return ""
        rows = [
            (
                a.author_label,
                a.finding_count,
                a.commit_count,
                f"{a.findings_per_commit:.4f}",
            )
            for a in report.author_rankings
        ]
        table = render_table(("Autor", "Achados", "Commits", "Achados por commit"), rows)
        return f'<h2>Ranking de autores</h2><div class="table-wrap">{table}</div>'

    def _warnings_block(self, report):
        if not report.warnings:
            return '<p class="muted">Nenhum aviso.</p>'
        items = "".join(f"<li>{esc(w)}</li>" for w in report.warnings)
        return f'<ul class="warnings">{items}</ul>'

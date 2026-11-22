"""Create downloadable PDFs from the same content as the offline HTML reports."""

from io import BytesIO

from xhtml2pdf import pisa

from analyzer.record import SessionRecord
from reports.generator.html import render


def render_pdf(record: SessionRecord, *, kind: str) -> bytes:
    output = BytesIO()
    try:
        status = pisa.CreatePDF(render(record, kind=kind, for_pdf=True), dest=output)
    except Exception as error:
        raise RuntimeError("PDF conversion failed") from error
    if status.err:
        raise RuntimeError("PDF conversion failed")
    return output.getvalue()

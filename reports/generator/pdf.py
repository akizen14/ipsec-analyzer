"""Create downloadable PDFs from the same content as the offline HTML reports."""

from io import BytesIO

from xhtml2pdf import pisa
from xhtml2pdf.config.resources import ResourceAccessPolicy

from analyzer.record import SessionRecord
from reports.generator.html import render

OFFLINE_POLICY = ResourceAccessPolicy.server(allow_remote=False)


def render_pdf(record: SessionRecord, *, kind: str) -> bytes:
    output = BytesIO()
    try:
        status = pisa.CreatePDF(
            render(record, kind=kind, for_pdf=True), dest=output, resource_policy=OFFLINE_POLICY,
        )
    except Exception as error:
        raise RuntimeError("PDF conversion failed") from error
    if status.err:
        raise RuntimeError("PDF conversion failed")
    return output.getvalue()

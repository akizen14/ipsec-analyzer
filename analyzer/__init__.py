"""IPsec VPN Protocol Analyzer and Security Assessment Framework.

Pipeline, in the order PLAN.md section 3 lays it out:

    ingest -> sessions -> {ike, esp_ah} -> inference -> rules -> scoring

Every stage writes into a session record (``analyzer.record``), which is the
contract between the analysis half and the product half. The dashboard and the
report generator read nothing but that record.
"""

__version__ = "0.1.0"

#: Version of the session record schema this build emits.
SCHEMA_VERSION = "1.0.0"

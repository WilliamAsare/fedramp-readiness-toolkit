# ADR 0001: OSCAL-first design with multi-format output

## Status

Accepted

## Context

FedRAMP has mandated OSCAL machine-readable formats for all authorization packages by September 2026. However, many CSPs and 3PAOs still work primarily with Word documents and Excel spreadsheets. We needed to decide whether to build the toolkit around traditional document formats, OSCAL, or both.

## Decision

OSCAL is the primary data format for all internal operations. Every script reads and writes OSCAL JSON as its native format. Traditional formats (DOCX, XLSX, CSV, HTML) are secondary outputs generated from the OSCAL data.

We use `compliance-trestle` (CNCF OSCAL Compass project) as the OSCAL SDK rather than raw JSON manipulation, because OSCAL documents are complex (the NIST catalog alone is 70,000+ lines) and the pydantic models catch structural errors at development time.

## Consequences

**Positive:** The toolkit is aligned with where FedRAMP is heading. CSPs who adopt OSCAL workflows now will have a smoother transition to 20x. The machine-readable format enables automation that's impossible with Word documents (gap analysis, validation, scoring all work because the data is structured).

**Negative:** There's an initial learning curve for teams unfamiliar with OSCAL. The `compliance-trestle` dependency adds complexity. Some 3PAOs still expect Word/Excel deliverables, so we must maintain the multi-format output capability.

**Mitigation:** Multi-format output from every script. Detailed OSCAL guide in docs. The SSP generator accepts human-friendly inputs (YAML + Markdown) and produces OSCAL output, hiding the format complexity.

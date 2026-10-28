from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import json
from xml.sax.saxutils import escape

def make_pdf_report(
    path, case, evidence, events, audit, disk_images=(), packet_captures=(),
    network_events=(), custody_events=(), case_notes=(), evaluation=None,
):
    doc = SimpleDocTemplate(path, pagesize=letter, rightMargin=0.55*inch, leftMargin=0.55*inch,
                            topMargin=0.55*inch, bottomMargin=0.55*inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=8, leading=10))
    story = [
        Paragraph("AI-DFIR Investigation Report", styles["Title"]),
        Paragraph(f"<b>Case:</b> {escape(str(case['title']))} (ID {case['id']})", styles["BodyText"]),
        Paragraph(f"<b>Created:</b> {escape(str(case['created_at']))}", styles["BodyText"]),
        Paragraph(
            f"<b>Status:</b> {escape(str(case.get('status') or 'Open'))} · "
            f"<b>Priority:</b> {escape(str(case.get('priority') or 'Routine'))} · "
            f"<b>Assigned to:</b> {escape(str(case.get('assignee') or 'Unassigned'))}",
            styles["BodyText"],
        ),
        Paragraph(f"<b>Description:</b> {escape(str(case.get('description') or 'Not provided'))}", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Executive summary", styles["Heading2"]),
        Paragraph(
            f"This case contains {len(evidence) + len(disk_images) + len(packet_captures)} registered "
            f"evidence item(s), {len(events) + len(network_events)} analyzed record(s), and "
            f"{sum(1 for event in events + network_events if event.get('severity') in ('medium', 'high'))} "
            "medium/high review lead(s). These are triage indicators requiring independent analyst review.",
            styles["BodyText"],
        ),
        Spacer(1, 12),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph(
            "This report summarizes an educational, automated analysis of uploaded evidence. Automated "
            "reputation results are contextual and do not prove malicious activity. Validate timestamps, "
            "parsing, provenance, network capture completeness, and conclusions independently. "
            "Actor names are self-reported unless a separate authenticated identity system is in use.",
            styles["BodyText"],
        ),
        Spacer(1, 12),
        Paragraph("Evidence files", styles["Heading2"])
    ]
    rows = [["Filename", "SHA-256", "Events", "Uploaded"]]
    for item in evidence:
        rows.append([Paragraph(escape(item["original_name"]), styles["SmallText"]),
                     Paragraph(escape(item["sha256"]), styles["SmallText"]),
                     str(item["event_count"]), Paragraph(escape(item["uploaded_at"]), styles["SmallText"])])
    t = Table(rows, colWidths=[1.45*inch, 3.0*inch, 0.55*inch, 1.45*inch], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16324F")),
                           ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
                           ("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),5)]))
    story += [t, Spacer(1, 12)]
    if disk_images:
        story.append(Paragraph("Disk-image examinations", styles["Heading2"]))
        for image in disk_images:
            analysis = json.loads(image.get("analysis_json") or "{}")
            recovery = json.loads(image.get("recovery_json") or "{}")
            story.append(Paragraph(
                f"<b>{escape(str(image['original_name']))}</b> — "
                f"{escape(str(image['image_type']).upper())}, "
                f"{int(image['size_bytes']):,} container bytes",
                styles["BodyText"],
            ))
            story.append(Paragraph(
                f"Container SHA-256: {escape(str(image['container_sha256']))}",
                styles["SmallText"],
            ))
            for segment in json.loads(image.get("segment_manifest") or "[]"):
                story.append(Paragraph(
                    f"Segment {escape(str(segment['name']))} "
                    f"({int(segment['size_bytes']):,} bytes) SHA-256: "
                    f"{escape(str(segment['sha256']))}",
                    styles["SmallText"],
                ))
            if analysis:
                story.append(Paragraph(
                    f"Logical image SHA-256: {escape(str(analysis.get('logical_sha256') or 'Unavailable'))}; "
                    f"decoded size: {int(analysis.get('logical_size_bytes') or 0):,} bytes",
                    styles["SmallText"],
                ))
                for index, partition in enumerate(analysis.get("partitions") or [], start=1):
                    listing = partition.get("file_listing") or {}
                    details = (
                        f"Partition {index}: {partition.get('description', 'Unknown')}; "
                        f"start sector {partition.get('start_sector', 'Unknown')}"
                    )
                    if listing:
                        details += (
                            f"; {listing.get('file_count', 0)} file entries, "
                            f"{listing.get('deleted_entry_count', 0)} marked deleted; "
                            f"listing SHA-256 {listing.get('listing_sha256', 'Unavailable')}"
                        )
                    elif partition.get("filesystem_error"):
                        details += f"; filesystem error: {partition['filesystem_error']}"
                    story.append(Paragraph(escape(details), styles["SmallText"]))
            else:
                story.append(Paragraph(
                    f"Image analysis status: {escape(str(image['analysis_status']))}",
                    styles["SmallText"],
                ))
            if recovery:
                story.append(Paragraph(
                    f"Recovery: {int(recovery.get('recovered_file_count') or 0)} files, "
                    f"{int(recovery.get('recovered_size_bytes') or 0):,} bytes; "
                    f"manifest SHA-256 {escape(str(recovery.get('manifest_sha256') or 'Unavailable'))}",
                    styles["SmallText"],
                ))
            story.append(Spacer(1, 8))
        story.append(Spacer(1, 8))
    if packet_captures:
        story.append(Paragraph("Packet-capture inventory and network analysis", styles["Heading2"]))
        for capture in packet_captures:
            summary = capture["summary"]
            story.append(Paragraph(
                f"<b>{escape(str(capture['original_name']))}</b> — "
                f"{int(capture['size_bytes']):,} bytes; {int(capture['packet_count']):,} packets; "
                f"{int(summary.get('unique_flows', 0))} flows; "
                f"{int(summary.get('unique_dns_queries', 0))} DNS request groups.",
                styles["BodyText"],
            ))
            story.append(Paragraph(
                f"SHA-256: {escape(str(capture['sha256']))}; "
                f"capture window: {escape(str(summary.get('first_seen') or 'Unknown'))} to "
                f"{escape(str(summary.get('last_seen') or 'Unknown'))}.",
                styles["SmallText"],
            ))
        for event in network_events[:250]:
            detail = event.get("details") or {}
            reasons = detail.get("reasons") or []
            story.append(Paragraph(
                f"{escape(str(event.get('timestamp') or 'Unknown'))} — "
                f"<b>{escape(str(event.get('severity') or 'info').upper())}</b> — "
                f"{escape(str(event.get('summary') or ''))}",
                styles["SmallText"],
            ))
            for reason in reasons:
                story.append(Paragraph(f"Review basis: {escape(str(reason))}", styles["SmallText"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph("Findings and event timeline", styles["Heading2"]))
    event_rows = [["Timestamp", "Severity", "Type", "Source IP", "Finding and recorded basis"]]
    for e in events[:250]:
        details = e.get("details") or {}
        reasons = details.get("reasons") or []
        basis = " ".join(str(reason) for reason in reasons)
        model = details.get("model")
        if model:
            basis += (
                f" Model anomaly score {model.get('anomaly_score', 'unavailable')}; "
                f"threshold {model.get('threshold', 'unavailable')}; "
                f"features {model.get('features', {})}; contributions {model.get('feature_contributions', {})}."
            )
        event_rows.append([
            Paragraph(escape(str(e.get("timestamp") or "Unknown")), styles["SmallText"]),
            escape(str(e.get("severity") or "info").upper()),
            Paragraph(escape(str(e.get("event_type") or "")), styles["SmallText"]),
            Paragraph(escape(str(e.get("source_ip") or "")), styles["SmallText"]),
            Paragraph(escape(f"{e.get('summary') or ''} {basis}".strip()), styles["SmallText"])
        ])
    if len(event_rows) == 1:
        event_rows.append(["—", "—", "No analysis", "—", "Run analysis to populate findings"])
    et = Table(event_rows, colWidths=[1.0*inch, 0.55*inch, 1.05*inch, 0.95*inch, 2.9*inch], repeatRows=1)
    et.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16324F")),
                            ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.grey),
                            ("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)]))
    story += [et, Spacer(1, 12), Paragraph("Detection evaluation", styles["Heading2"])]
    evaluation = evaluation or {}
    percent = lambda key: (
        f"{evaluation[key] * 100:.1f}%" if evaluation.get(key) is not None else "Not measured"
    )
    story.append(Paragraph(
        f"Labeled findings: {evaluation.get('labeled_count', 0)}; "
        f"precision: {percent('precision')}; recall: {percent('recall')}; "
        f"false-positive rate: {percent('false_positive_rate')}. "
        f"Rule-flagged records: {evaluation.get('rule_flagged', 0)}; "
        f"model-flagged records: {evaluation.get('model_flagged', 0)}. "
        "Metrics are computed only from investigator-labeled outcomes; they are not representative "
        "without a suitable labeled test set.",
        styles["BodyText"],
    ))
    if case_notes:
        story += [Spacer(1, 12), Paragraph("Analyst notes", styles["Heading2"])]
        for note in case_notes[:100]:
            story.append(Paragraph(
                f"{escape(str(note['created_at']))} — <b>{escape(str(note['actor']))}</b>: "
                f"{escape(str(note['note']))}",
                styles["SmallText"],
            ))
    if custody_events:
        story += [Spacer(1, 12), Paragraph("Chain of custody", styles["Heading2"])]
        custody_rows = [["Date / time (UTC)", "Action", "Evidence item", "Actor", "SHA-256 before", "SHA-256 after", "Transfer / note"]]
        for item in custody_events[:250]:
            transfer = ""
            if item.get("from_actor") or item.get("to_actor"):
                transfer = f"{item.get('from_actor') or ''} → {item.get('to_actor') or ''}"
            custody_rows.append([
                Paragraph(escape(str(item["occurred_at"])), styles["SmallText"]),
                Paragraph(escape(str(item["action"])), styles["SmallText"]),
                Paragraph(escape(str(item["evidence_name"])), styles["SmallText"]),
                Paragraph(escape(str(item["actor"])), styles["SmallText"]),
                Paragraph(escape(str(item.get("sha256_before") or "—")), styles["SmallText"]),
                Paragraph(escape(str(item.get("sha256_after") or "—")), styles["SmallText"]),
                Paragraph(escape(f"{transfer} {item.get('details') or ''}".strip()), styles["SmallText"]),
            ])
        custody_table = Table(
            custody_rows, colWidths=[0.9*inch, 0.9*inch, 1.0*inch, 0.85*inch, 1.15*inch, 1.15*inch, 1.0*inch],
            repeatRows=1,
        )
        custody_table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#16324F")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.35,colors.grey),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("FONTSIZE",(0,0),(-1,-1),7),
            ("PADDING",(0,0),(-1,-1),4),
        ]))
        story.append(custody_table)
    story += [Spacer(1, 12), Paragraph("Audit trail", styles["Heading2"])]
    for a in audit[:50]:
        story.append(Paragraph(
            f"{escape(str(a['timestamp']))} — <b>{escape(str(a['action']))}</b> "
            f"({escape(str(a.get('actor') or 'Unattributed'))}): "
            f"{escape(str(a.get('details') or ''))}",
            styles["SmallText"],
        ))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Forensic caution: preserve original evidence, document acquisition and handling, and have a qualified reviewer validate every conclusion.", styles["Italic"]))
    doc.build(story)

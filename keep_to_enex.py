#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import html
import io
import json
import mimetypes
import os
import re
import sys
import zipfile
from pathlib import Path

ENEX_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE en-export SYSTEM "http://xml.evernote.com/pub/evernote-export3.dtd">
<en-export export-date="{export_date}" application="keep-to-enex" version="1.0">
"""
ENEX_FOOTER = "</en-export>\n"

# ENML content wrapper (required by ENEX)
def enml_wrap(inner_html: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE en-note SYSTEM "http://xml.evernote.com/pub/enml2.dtd">'
        f"<en-note>{inner_html}</en-note>"
    )

def ts_usec_to_enex_time(usec: int) -> str:
    """Google Keep uses microseconds since epoch. ENEX wants UTC in YYYYMMDDThhmmssZ."""
    # If it's already small (ms/sec), try to normalize
    if usec < 10_000_000_000:  # seconds
        dt_ = dt.datetime.utcfromtimestamp(usec)
    elif usec < 10_000_000_000_000:  # milliseconds
        dt_ = dt.datetime.utcfromtimestamp(usec / 1000.0)
    else:  # microseconds
        dt_ = dt.datetime.utcfromtimestamp(usec / 1_000_000.0)
    return dt_.strftime("%Y%m%dT%H%M%SZ")

def guess_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or "application/octet-stream"

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sanitize_text(s: str) -> str:
    # Minimal cleanup; ENML will escape via html.escape inside content as needed
    return s.replace("\r\n", "\n").strip()

def build_checklist_html(list_items):
    """Render Keep checklist to ENML using en-todo."""
    parts = []
    for item in list_items:
        text = html.escape(item.get("text", ""))
        checked = "true" if item.get("isChecked") else "false"
        parts.append(f'<div><en-todo checked="{checked}"/>{text}</div>')
    return "".join(parts)

def build_plain_text_html(text: str) -> str:
    # Convert simple line breaks to <div> lines
    lines = [f"<div>{html.escape(line)}</div>" for line in text.split("\n")]
    return "".join(lines)

def load_keep_jsons_from_zip(zf: zipfile.ZipFile):
    # Keep items live under Takeout/Keep/*.json typically
    for name in zf.namelist():
        if name.lower().endswith(".json") and "/keep/" in name.lower():
            with zf.open(name) as fp:
                try:
                    yield name, json.load(fp)
                except Exception:
                    continue

def load_keep_jsons_from_dir(root: Path):
    for p in sorted(root.glob("*.json")):
        try:
            yield str(p), json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue

def read_attachment_bytes(get_bytes, file_rel_path):
    try:
        return get_bytes(file_rel_path)
    except KeyError:
        # Sometimes Takeout references paths like "attachments/..."
        # Try a more lenient match
        basename = os.path.basename(file_rel_path)
        return get_bytes(basename)

def make_note_enex(note, get_bytes):
    """
    Build a single <note>...</note> ENEX fragment.
    `get_bytes(path)` must return raw bytes for attachments by relative path.
    """
    title = sanitize_text(note.get("title") or "")
    text = sanitize_text(note.get("textContent") or "")
    created_ts = note.get("createdTimestampUsec") or note.get("createdTimestamp")
    updated_ts = note.get("userEditedTimestampUsec") or note.get("userEditedTimestamp")
    created = ts_usec_to_enex_time(int(created_ts)) if created_ts else dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    updated = ts_usec_to_enex_time(int(updated_ts)) if updated_ts else created

    labels = [lb.get("name") for lb in note.get("labels", []) if lb.get("name")]
    tags = set(labels)

    if note.get("isPinned"):
        tags.add("keep-pinned")
    if note.get("isArchived"):
        tags.add("keep-archived")
    if note.get("color"):
        tags.add(f'keep-color-{str(note.get("color")).lower()}')
    if note.get("isTrashed"):
        tags.add("keep-trashed")
    if note.get("isDraft"):  # rare
        tags.add("keep-draft")
    if note.get("isRemindersSet") or note.get("reminders"):
        tags.add("keep-reminder")

    # Content building
    html_body = []
    if text:
        html_body.append(build_plain_text_html(text))

    # Checklist (Keep uses listContent as array of items with isChecked/text)
    if note.get("listContent"):
        html_body.append(build_checklist_html(note["listContent"]))

    resources_xml = []
    resource_hashes_in_body = []

    # Attachments
    for att in note.get("attachments", []):
        fp = att.get("filePath") or att.get("path") or att.get("blobRef")  # Takeout usually stores 'filePath'
        if not fp:
            continue
        try:
            data = read_attachment_bytes(get_bytes, fp)
        except Exception:
            continue

        mime = guess_mime(fp)
        hash_hex = md5_hex(data)
        b64 = base64.b64encode(data).decode("ascii")
        fname = os.path.basename(fp)

        # ENML <en-media> tag in body references resource via MD5 hash
        resource_hashes_in_body.append((hash_hex, mime))
        resources_xml.append(
            "  <resource>\n"
            f"    <data encoding=\"base64\">{b64}</data>\n"
            f"    <mime>{html.escape(mime)}</mime>\n"
            "    <resource-attributes>\n"
            f"      <file-name>{html.escape(fname)}</file-name>\n"
            "    </resource-attributes>\n"
            "  </resource>\n"
        )

    # Place media elements after text/checklist so they appear at the end
    for h, m in resource_hashes_in_body:
        html_body.append(f'<div><en-media type="{html.escape(m)}" hash="{h}"/></div>')

    inner = "".join(html_body) if html_body else "<div></div>"
    content = enml_wrap(inner)

    # Build the note XML
    parts = []
    parts.append("<note>\n")
    parts.append(f"  <title>{html.escape(title) if title else 'Untitled'}</title>\n")
    parts.append(f"  <content><![CDATA[{content}]]></content>\n")
    parts.append(f"  <created>{created}</created>\n")
    parts.append(f"  <updated>{updated}</updated>\n")

    for tag in sorted(tags):
        parts.append(f"  <tag>{html.escape(tag)}</tag>\n")

    # Keep a breadcrumb of origin
    parts.append("  <note-attributes>\n")
    parts.append("    <source>google-keep</source>\n")
    if note.get("color"):
        parts.append(f"    <source-application>keep-color:{html.escape(str(note['color']))}</source-application>\n")
    parts.append("  </note-attributes>\n")

    # Resources
    parts.extend(resources_xml)

    parts.append("</note>\n")
    return "".join(parts)

def parse_input_source(input_path: Path):
    """
    Returns a tuple:
      - iter_notes: iterator over (name, note_json)
      - get_bytes: function(relative_path)->bytes for attachments
    """
    if input_path.is_file() and input_path.suffix.lower() == ".zip":
        zf = zipfile.ZipFile(input_path, "r")

        def get_bytes(rel):
            # Normalize path to the actual Keep folder
            # Try exact, Try with Takeout/Keep prefix, try scanning
            # First: direct
            try:
                return zf.read(rel)
            except KeyError:
                pass
            # Try under */Keep/
            for cand in (
                f"Takeout/Keep/{rel}",
                f"keep/{rel}",
                f"Keep/{rel}",
            ):
                try:
                    return zf.read(cand)
                except KeyError:
                    continue
            # Fallback search by basename
            base = os.path.basename(rel).lower()
            for name in zf.namelist():
                if name.lower().endswith("/" + base) or name.lower().endswith(base):
                    return zf.read(name)
            raise KeyError(rel)

        return load_keep_jsons_from_zip(zf), get_bytes

    # Directory
    keep_dir = input_path
    if keep_dir.is_dir():
        # If user pointed to Takeout root, descend into Keep
        if (keep_dir / "Keep").exists():
            keep_dir = keep_dir / "Keep"

        def get_bytes(rel):
            for cand in (
                keep_dir / rel,
                keep_dir / Path(rel).name,
            ):
                if cand.exists():
                    return cand.read_bytes()
            # Scan for basename if needed
            base = Path(rel).name.lower()
            for p in keep_dir.rglob("*"):
                if p.is_file() and p.name.lower() == base:
                    return p.read_bytes()
            raise KeyError(rel)

        return load_keep_jsons_from_dir(keep_dir), get_bytes

    raise FileNotFoundError(f"Input path not found or unsupported: {input_path}")

def main():
    ap = argparse.ArgumentParser(description="Convert Google Keep (Takeout) export to an Evernote .enex file for Apple Notes import.")
    ap.add_argument("--input", "-i", required=True, help="Path to Takeout.zip or Takeout/Keep directory")
    ap.add_argument("--output", "-o", default="keep.enex", help="Output ENEX filename (default: keep.enex)")
    ap.add_argument("--limit", type=int, default=0, help="Optional limit of notes to convert (debug)")
    args = ap.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    iter_notes, get_bytes = parse_input_source(input_path)

    export_date = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    count = 0
    converted = 0

    with io.open(output_path, "w", encoding="utf-8") as out:
        out.write(ENEX_HEADER.format(export_date=export_date))
        for name, note in iter_notes:
            count += 1
            if args.limit and converted >= args.limit:
                break
            try:
                frag = make_note_enex(note, get_bytes)
                out.write(frag)
                converted += 1
            except Exception as e:
                # Fail soft on a single note, but keep going
                sys.stderr.write(f"[WARN] Failed on {name}: {e}\n")
        out.write(ENEX_FOOTER)

    print(f"Processed: {count} notes | Converted: {converted} | Output: {output_path}")

if __name__ == "__main__":
    # Ensure .md/.jpg default mime guesses
    mimetypes.add_type("text/markdown", ".md")
    mimetypes.add_type("image/webp", ".webp")
    main()

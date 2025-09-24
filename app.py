# streamlit_app.py
# Full Streamlit dashboard with Excel-like in-column filters (AG Grid),
# ScanOSS JSON/YAML parsing, KPI cards, license pie chart (Altair),
# and filtered Excel export.

import io
import json
from datetime import datetime

import pandas as pd
import streamlit as st
import altair as alt

# Optional dependencies
try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode
    _HAS_AGGRID = True
except Exception:
    _HAS_AGGRID = False

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

# ---------------------------
# Page config
# ---------------------------
# Toggle this to True only if you have AG Grid Enterprise available
USE_SET_FILTER = False
# ---------------------------
st.set_page_config(
    page_title="OSS Compliance – JSON/YAML Dashboard",
    layout="wide",
)

# ---------------------------
# Session state init
# ---------------------------
DEFAULT_STATE = {
    "uploaded_file": None,
    "file_name": "",
    "uploaded": False,       # file is chosen
    "processed": False,      # after clicking Scan / Process
    "kpis": {
        "files_scanned": 0,
        "components_total": 0,
        "unique_licenses": 0,
        "vulnerabilities": 0,
        "with_dependencies": 0,
    },
    "findings_df": pd.DataFrame(),
    "export_df": pd.DataFrame(),
    "table_df": pd.DataFrame(),
}

for k, v in DEFAULT_STATE.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------
# Helpers
# ---------------------------
SEVERITY_ORDER = {"critical": 5, "high": 4, "moderate": 3, "medium": 3, "low": 2, "none": 1, None: 0}


def reset_state():
    for k, v in DEFAULT_STATE.items():
        st.session_state[k] = v


def _load_structured(file) -> dict:
    """Load JSON or YAML into a Python dict."""
    raw = file.getvalue()
    text = raw.decode("utf-8", errors="ignore")
    # Try JSON first
    try:
        return json.loads(text)
    except Exception:
        pass
    # Try YAML if available
    if _HAS_YAML:
        try:
            return yaml.safe_load(text)
        except Exception:
            pass
    raise ValueError("Unsupported or malformed file. Please upload valid JSON or YAML.")


def _is_match_list(v) -> bool:
    return isinstance(v, list) and (len(v) == 0 or isinstance(v[0], dict))


def parse_scanoss_payload(payload: dict) -> pd.DataFrame:
    """Flatten typical ScanOSS output into a DataFrame.
    Expected structure: top-level keys are file paths; values are lists of match dicts.
    """
    rows = []
    if not isinstance(payload, dict):
        return pd.DataFrame()

    for file_path, matches in payload.items():
        if not _is_match_list(matches):
            # skip non-match sections
            continue
        for m in matches:
            component = m.get("component")
            version = m.get("version")
            vendor = m.get("vendor")
            matched = m.get("matched") or m.get("match")
            release_date = m.get("release_date") or m.get("released")
            health = m.get("health") or {}
            stars = health.get("stars") if isinstance(health, dict) else None
            forks = health.get("forks") if isinstance(health, dict) else None

            # licenses
            licenses = m.get("licenses") or []
            lic_names = []
            lic_sources = []
            for lic in licenses:
                if isinstance(lic, dict):
                    name = lic.get("name") or lic.get("license")
                    if name:
                        lic_names.append(str(name))
                    src = lic.get("source")
                    if src:
                        lic_sources.append(str(src))
                elif isinstance(lic, str):
                    lic_names.append(lic)

            # vulnerabilities
            vulns = m.get("vulnerabilities") or []
            vuln_count = 0
            highest = None
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vuln_count += 1
                sev = (v.get("severity") or "").lower() or None
                if highest is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(highest, 0):
                    highest = sev

            # purls
            purls = m.get("purl") or m.get("purls") or []
            if isinstance(purls, str):
                purls = [purls]

            # sources / evidence
            sources = set(lic_sources)
            prov = m.get("provenance")
            if isinstance(prov, list):
                sources.update([str(x) for x in prov])
            elif isinstance(prov, str):
                sources.add(prov)

            # dependencies flag
            deps = m.get("dependencies")
            has_deps = bool(deps) and isinstance(deps, (list, dict)) and len(deps) > 0

            rows.append({
                "File": file_path,
                "Component": component or "—",
                "Version": version or "—",
                "Licenses": ", ".join(sorted(set(lic_names))) or "—",
                "Vulns": vuln_count,
                "HighestSeverity": (highest or "none").capitalize() if highest else "None",
                "PURLs": ", ".join(purls) if purls else "—",
                "Vendor": vendor or "—",
                "Match %": matched or "—",
                "Sources": "; ".join(sorted(sources)) if sources else "—",
                "Health": (f"★ {int(stars)} / {int(forks)}" if (isinstance(stars, (int, float)) and isinstance(forks, (int, float))) else "—"),
                "Release Date": release_date or "—",
                "_HasDeps": has_deps,
                "_LicList": lic_names,
            })
    return pd.DataFrame(rows)


def compute_kpis(df: pd.DataFrame) -> dict:
    if df.empty:
        return DEFAULT_STATE["kpis"].copy()
    files_scanned = df["File"].nunique()
    components_total = len(df)
    # collect unique license names from helper list
    unique_licenses = 0
    try:
        all_lics = set([lic for row in df["_LicList"].tolist() for lic in (row or [])])
        unique_licenses = len(all_lics)
    except Exception:
        unique_licenses = 0
    vulnerabilities = int(df["Vulns"].sum()) if "Vulns" in df.columns else 0
    with_dependencies = int(df["_HasDeps"].sum()) if "_HasDeps" in df.columns else 0
    return {
        "files_scanned": int(files_scanned),
        "components_total": int(components_total),
        "unique_licenses": int(unique_licenses),
        "vulnerabilities": int(vulnerabilities),
        "with_dependencies": int(with_dependencies),
    }

# ---------------------------
# Header / Controls row
# ---------------------------
left, right = st.columns([2, 1])
with left:
    st.title("OSS Compliance – JSON/YAML Dashboard")
    st.caption("Upload ScanOSS results, click **Scan / Process**, then export to Excel.")
with right:
    with st.container(border=True):
        uploaded_file = st.file_uploader(
            "Upload JSON/YAML",
            type=["json", "yml", "yaml"],
            label_visibility="visible",
            help="Upload ScanOSS output as JSON or YAML.",
            key="uploader",
        )
        if uploaded_file is not None:
            prev_name = st.session_state.get("file_name")
            # Only mark as a fresh upload if name changed or not previously uploaded
            if not st.session_state.get("uploaded") or uploaded_file.name != prev_name:
                st.session_state["uploaded_file"] = uploaded_file
                st.session_state["file_name"] = uploaded_file.name
                st.session_state["uploaded"] = True
                st.session_state["processed"] = False

        # Buttons stacked vertically in the header
        process_disabled = not st.session_state["uploaded"]
        if st.button("🔎 Scan / Process", type="primary", disabled=process_disabled, help="Process the uploaded file"):
            try:
                payload = _load_structured(st.session_state["uploaded_file"])
                df = parse_scanoss_payload(payload)
            except Exception as e:
                st.session_state["processed"] = False
                st.error(f"Failed to parse file: {e}")
                df = pd.DataFrame()
            else:
                st.session_state["processed"] = True
            st.session_state["findings_df"] = df
            st.session_state["kpis"] = compute_kpis(df)
            # Freeze a stable copy for display until next Scan
            helper_cols = ["_HasDeps", "_LicList"]
            stable_df = df.drop(columns=[c for c in helper_cols if c in df.columns]).copy()
            st.session_state["table_df"] = stable_df
            st.session_state["export_df"] = stable_df.copy()

        if st.session_state["processed"] and not st.session_state["findings_df"].empty:
            export_df = st.session_state.get("export_df", st.session_state["findings_df"]).copy()
            df_to_export = export_df.drop(columns=[c for c in ["_HasDeps", "_LicList"] if c in export_df.columns])
            buf = io.BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                df_to_export.to_excel(writer, sheet_name="Findings", index=False)
            st.download_button(
                label="📥 Export to Excel",
                data=buf.getvalue(),
                file_name=f"oss_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                help="Download the current (filtered) table as Excel",
            )
        else:
            st.button("📥 Export to Excel", disabled=True)

        if st.button("🧹 Clear", help="Reset the dashboard"):
            reset_state()
            st.experimental_rerun()

# ---------------------------
# Status bar
# ---------------------------
if not st.session_state["uploaded"] and not st.session_state["processed"]:
    st.info("**Status:** idle · Upload a JSON/YAML to begin.")
elif st.session_state["uploaded"] and not st.session_state["processed"]:
    st.warning(f"**Status:** awaiting *Scan / Process* · Uploaded: **{st.session_state['file_name'] or 'data.json'}**")
elif st.session_state["processed"]:
    st.success(f"**Status:** data ready · Processed: **{st.session_state['file_name'] or 'data.json'}**")

st.divider()

# ---------------------------
# KPI row
# ---------------------------
if st.session_state["processed"]:
    k = st.session_state["kpis"]
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Files Scanned", k.get("files_scanned", 0))
    k2.metric("Total Components", k.get("components_total", 0))
    k3.metric("Unique Licenses", k.get("unique_licenses", 0))
    k4.metric("Vulnerabilities", k.get("vulnerabilities", 0))
    k5.metric("With Dependencies", k.get("with_dependencies", 0))
else:
    st.caption("KPI cards will appear here after you click **Scan / Process**.")

# ---------------------------
# License Pie Chart (Altair)
# ---------------------------
if st.session_state["processed"] and not st.session_state["findings_df"].empty:
    df_base = st.session_state["findings_df"]
    lic_counts = {}
    for lst in df_base.get("_LicList", []):
        if isinstance(lst, list):
            for name in lst:
                if not name:
                    continue
                lic_counts[name] = lic_counts.get(name, 0) + 1
    if not lic_counts and not df_base.empty:
        for s in df_base["Licenses"].astype(str).tolist():
            for name in [x.strip() for x in s.split(",") if x.strip() and x.strip() != "—"]:
                lic_counts[name] = lic_counts.get(name, 0) + 1

    if lic_counts:
        st.subheader("License Distribution")
        chart_df = pd.DataFrame({"License": list(lic_counts.keys()), "Count": list(lic_counts.values())})
        if len(chart_df) > 10:
            top = chart_df.sort_values("Count", ascending=False).head(10)
            others = pd.DataFrame({"License": ["Others"], "Count": [int(chart_df.iloc[10:]["Count"].sum())]})
            chart_df = pd.concat([top, others], ignore_index=True)
        pie = alt.Chart(chart_df).mark_arc().encode(
            theta=alt.Theta(field="Count", type="quantitative"),
            color=alt.Color(field="License", type="nominal"),
            tooltip=["License", "Count"],
        )
        st.altair_chart(pie, use_container_width=True)

# ---------------------------
# Findings table (AG Grid with Excel-like header filters)
# ---------------------------
with st.container(border=True):
    st.subheader("Findings")

    has_table = st.session_state.get("table_df", pd.DataFrame()).shape[0] > 0

    if has_table:
        # Always render the stable table created at Scan time
        df_show = st.session_state.get("table_df", pd.DataFrame()).copy()
        if df_show.empty:
            df_base = st.session_state["findings_df"].copy()
            helper_cols = ["_HasDeps", "_LicList"]
            df_show = df_base.drop(columns=[c for c in helper_cols if c in df_base.columns])

        if _HAS_AGGRID:
            # Always show header icons (menu/filter) like Excel
            st.markdown(
                """
                <style>
                .ag-theme-streamlit .ag-header-cell .ag-header-icon { opacity: 1 !important; }
                </style>
                """,
                unsafe_allow_html=True,
            )

            gb = GridOptionsBuilder.from_dataframe(df_show)
            gb.configure_default_column(
                filter=True,
                floatingFilter=True,
                sortable=True,
                resizable=True,
            )
            # Keep menu icons visible
            gb.configure_grid_options(suppressMenuHide=True)

            # Column-specific filter types
            for col in df_show.columns:
                if pd.api.types.is_numeric_dtype(df_show[col]):
                    gb.configure_column(col, filter="agNumberColumnFilter")
                else:
                    # Use Set Filter only if enterprise is enabled; otherwise fallback to Text Filter
                    if USE_SET_FILTER and col in ("Licenses", "HighestSeverity", "Vendor", "Sources"):
                        gb.configure_column(col, filter="agSetColumnFilter")
                    else:
                        gb.configure_column(col, filter="agTextColumnFilter")

            grid_options = gb.build()
            # Funnel icon glyph for menu/filter
            funnel_svg = '<svg width="12" height="12" viewBox="0 0 24 24"><path d="M3 5h18l-7 7v7l-4-2v-5z" fill="currentColor"/></svg>'
            grid_options["icons"] = {
                "menu": funnel_svg,
                "filter": funnel_svg,
                "filterActive": funnel_svg,
            }

            grid_resp = AgGrid(
                df_show,
                gridOptions=grid_options,
                theme="streamlit",
                update_mode=GridUpdateMode.NO_UPDATE,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                allow_unsafe_jscode=True,
                height=480,
                key="findings_grid",
            )

            # To avoid full-page reruns on each keystroke, we don't update on every model change.
            # Click the button below to sync the filtered table into Export.
            if st.button("🔄 Sync Export from Table"):
                resp_data = grid_resp.get("data")
                if isinstance(resp_data, pd.DataFrame) and not resp_data.empty:
                    st.session_state["export_df"] = resp_data.copy()
                else:
                    try:
                        temp_df = pd.DataFrame(resp_data)
                        st.session_state["export_df"] = temp_df.copy() if not temp_df.empty else df_show.copy()
                    except Exception:
                        st.session_state["export_df"] = df_show.copy()
                st.success("Export view updated from current table filters.")
        else:
            st.warning("In-table column filters require 'streamlit-aggrid'. Showing a basic table instead. Install with: pip install streamlit-aggrid")
            st.dataframe(df_show, use_container_width=True)
            st.session_state["export_df"] = df_show

        st.caption(f"Rows: {len(st.session_state['export_df'])}")
    elif st.session_state["processed"] and st.session_state["findings_df"].empty:
        st.warning("Parsed successfully but no match rows found.")
    else:
        st.info("No rows yet. Upload a file and click **Scan / Process**.")

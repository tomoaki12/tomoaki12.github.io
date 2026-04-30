"""
jp_security_monitor.py
======================
JVN / JPCERT/CC / IPA から日本関連の脆弱性情報と
SecurityNext からセキュリティニュースを収集し HTML ダッシュボードを生成する。

必要ライブラリ:
    pip install requests beautifulsoup4

環境変数（.env）:
    ANTHROPIC_API_KEY=sk-ant-xxxxx  # オプション
"""

import json, os, re, sys, time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("pip install requests beautifulsoup4 を実行してください")
    sys.exit(1)

BASE_DIR  = Path(__file__).parent
HTML_FILE = BASE_DIR / "index.html"
SEEN_FILE = BASE_DIR / "jp_security_seen.json"
LOG_FILE  = BASE_DIR / "jp_security_monitor.log"
ENV_FILE  = BASE_DIR / ".env"
JST = timezone(timedelta(hours=9))

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
    "Accept": "application/rss+xml,application/xml,text/xml,*/*;q=0.8",
}

def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ── ユーティリティ ────────────────────────────────────────
def log(msg):
    ts = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def load_seen():
    if SEEN_FILE.exists():
        with open(SEEN_FILE, encoding="utf-8") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(seen), f, ensure_ascii=False, indent=2)

def make_id(category, source, url):
    return f"{category}|{source}|{url}".lower().strip()

def new_session():
    s = requests.Session()
    s.headers.update(HEADERS)
    return s

def cvss_label(score_str):
    try:
        score = float(score_str)
        if score >= 9.0: return "Critical", "#f85149"
        if score >= 7.0: return "High",     "#f0883e"
        if score >= 4.0: return "Medium",   "#d29922"
        return "Low", "#3fb950"
    except (ValueError, TypeError):
        return "", "#8b949e"

def parse_date(raw):
    """様々な日付フォーマットを YYYY-MM-DD に正規化"""
    if not raw:
        return ""
    raw = raw.strip()
    # ISO 8601
    m = re.search(r'(\d{4}-\d{2}-\d{2})', raw)
    if m:
        return m.group(1)
    # RFC 822: Thu, 30 Apr 2026 09:00:00 +0900
    months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
               "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
    m = re.search(r'(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})', raw)
    if m:
        d, mon, y = m.groups()
        return f"{y}-{months.get(mon.capitalize(),'00')}-{d.zfill(2)}"
    return raw[:10]

def strip_html(text):
    if not text:
        return ""
    return BeautifulSoup(text, "html.parser").get_text(" ").strip()

def fetch_rdf(url, source_name, category):
    """RDF 1.0 / RSS 1.0 フィードを取得してレコードリストを返す"""
    results = []
    s = new_session()
    try:
        r = s.get(url, timeout=20)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        RSS = "http://purl.org/rss/1.0/"
        DC  = "http://purl.org/dc/elements/1.1/"
        for item in root.findall(f"{{{RSS}}}item"):
            title = item.findtext(f"{{{RSS}}}title", "").strip()
            link  = item.findtext(f"{{{RSS}}}link",  "").strip()
            desc  = item.findtext(f"{{{RSS}}}description", "").strip()
            date  = item.findtext(f"{{{DC}}}date", "").strip()
            if not title:
                continue
            results.append({
                "日付":       parse_date(date),
                "ソース":     source_name,
                "カテゴリ":   category,
                "タイトル":   title,
                "深刻度":     "",
                "深刻度色":   "#8b949e",
                "CVE":        "",
                "説明":       strip_html(desc)[:200],
                "URL":        link,
            })
    except Exception as e:
        log(f"{source_name} エラー: {e}")
    log(f"{source_name}: {len(results)}件")
    return results

def fetch_rss2(url, source_name, category):
    """RSS 2.0 / Atom フィードを取得してレコードリストを返す"""
    results = []
    s = new_session()
    try:
        r = s.get(url, timeout=20)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        # RSS 2.0
        for item in root.findall(".//item"):
            title   = item.findtext("title",   "").strip()
            link    = item.findtext("link",    "").strip()
            desc    = item.findtext("description", "").strip()
            pubdate = item.findtext("pubDate", "").strip()
            if not title:
                continue
            results.append({
                "日付":       parse_date(pubdate),
                "ソース":     source_name,
                "カテゴリ":   category,
                "タイトル":   title,
                "深刻度":     "",
                "深刻度色":   "#8b949e",
                "CVE":        "",
                "説明":       strip_html(desc)[:200],
                "URL":        link,
            })
        # Atom
        if not results:
            ATOM = "http://www.w3.org/2005/Atom"
            for entry in root.findall(f"{{{ATOM}}}entry"):
                title   = entry.findtext(f"{{{ATOM}}}title", "").strip()
                link_el = entry.find(f"{{{ATOM}}}link")
                link    = link_el.get("href", "") if link_el is not None else ""
                summary = entry.findtext(f"{{{ATOM}}}summary", "").strip()
                updated = entry.findtext(f"{{{ATOM}}}updated", "").strip()
                if not title:
                    continue
                results.append({
                    "日付":       parse_date(updated),
                    "ソース":     source_name,
                    "カテゴリ":   category,
                    "タイトル":   title,
                    "深刻度":     "",
                    "深刻度色":   "#8b949e",
                    "CVE":        "",
                    "説明":       strip_html(summary)[:200],
                    "URL":        link,
                })
    except Exception as e:
        log(f"{source_name} エラー: {e}")
    log(f"{source_name}: {len(results)}件")
    return results

# ── JVN iPedia MyJVN API ──────────────────────────────────
def fetch_jvndb():
    """JVN iPedia から CVSS スコア付き脆弱性一覧を取得"""
    results = []
    s = new_session()
    now = datetime.now(JST)

    for months_ago in range(2):
        target = (now.replace(day=1) - timedelta(days=30 * months_ago))
        params = {
            "method":            "getVulnOverviewList",
            "feed":              "hnd",
            "datePublicStartY":  target.year,
            "datePublicStartM":  f"{target.month:02d}",
            "datePublicStartD":  "01",
            "datePublicEndY":    target.year,
            "datePublicEndM":    f"{target.month:02d}",
            "datePublicEndD":    "31",
        }
        try:
            r = s.get("https://jvndb.jvn.jp/myjvn", params=params, timeout=30)
            if r.status_code != 200:
                log(f"JVN iPedia HTTP {r.status_code}")
                continue
            root = ET.fromstring(r.content)

            SEC  = "http://jvn.jp/rss/mod_sec/3.0/"
            RSS  = "http://purl.org/rss/1.0/"
            DC   = "http://purl.org/dc/elements/1.1/"

            for item in root.findall(f"{{{RSS}}}item"):
                title  = item.findtext(f"{{{RSS}}}title", "").strip()
                link   = item.findtext(f"{{{RSS}}}link",  "").strip()
                desc   = item.findtext(f"{{{RSS}}}description", "").strip()
                date   = item.findtext(f"{{{DC}}}date", "").strip()

                # CVSS スコア
                cvss_el = item.find(f".//{{{SEC}}}cvss")
                score   = cvss_el.get("score", "") if cvss_el is not None else ""

                # CVE IDs
                cves = []
                for ref in item.findall(f".//{{{SEC}}}references"):
                    ref_id = ref.get("id", "")
                    if ref_id.upper().startswith("CVE-"):
                        cves.append(ref_id.upper())

                label, color = cvss_label(score)
                if not title:
                    continue
                results.append({
                    "日付":       parse_date(date),
                    "ソース":     "JVN iPedia",
                    "カテゴリ":   "脆弱性",
                    "タイトル":   title,
                    "深刻度":     f"{label} {score}".strip() if label else score,
                    "深刻度色":   color,
                    "CVE":        ", ".join(cves),
                    "説明":       strip_html(desc)[:200],
                    "URL":        link,
                })
        except Exception as e:
            log(f"JVN iPedia エラー ({target.year}/{target.month}): {e}")

    log(f"JVN iPedia: {len(results)}件")
    return results

# ── SecurityNext スクレイピング ───────────────────────────
def fetch_security_next():
    """SecurityNext から最新ニュースを取得"""
    results = []
    s = new_session()
    try:
        r = s.get("https://www.security-next.com/feed", timeout=20)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        for item in root.findall(".//item"):
            title   = item.findtext("title",   "").strip()
            link    = item.findtext("link",    "").strip()
            desc    = item.findtext("description", "").strip()
            pubdate = item.findtext("pubDate", "").strip()
            if not title:
                continue
            results.append({
                "日付":       parse_date(pubdate),
                "ソース":     "SecurityNext",
                "カテゴリ":   "ニュース",
                "タイトル":   title,
                "深刻度":     "",
                "深刻度色":   "#8b949e",
                "CVE":        "",
                "説明":       strip_html(desc)[:200],
                "URL":        link,
            })
    except Exception as e:
        log(f"SecurityNext エラー: {e}")
    log(f"SecurityNext: {len(results)}件")
    return results


# ── HTML 生成 ─────────────────────────────────────────────
def generate_html(all_records):
    now_str     = datetime.now(JST).strftime("%Y年%m月%d日 %H:%M JST")
    vulns       = [r for r in all_records if r["カテゴリ"] == "脆弱性"]
    news        = [r for r in all_records if r["カテゴリ"] == "ニュース"]
    high_count  = sum(1 for r in vulns if "Critical" in r["深刻度"] or "High" in r["深刻度"])

    def safe(v):
        return str(v or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def linkify(url, text):
        if not url:
            return safe(text)
        return f'<a href="{safe(url)}" target="_blank" rel="noopener">{safe(text)}</a>'

    def sev_badge(r):
        sev  = r.get("深刻度", "")
        color = r.get("深刻度色", "#8b949e")
        if not sev:
            return '<span class="na">—</span>'
        return f'<span class="sev-badge" style="border-color:{safe(color)};color:{safe(color)}">{safe(sev)}</span>'

    def source_badge(src):
        colors = {
            "JVN iPedia":     "#58a6ff",
            "JVN":            "#79c0ff",
            "JPCERT 注意喚起": "#f0883e",
            "JPCERT 緊急":    "#f85149",
            "IPA 脆弱性":     "#d29922",
            "IPA 重要脆弱性": "#d29922",
            "SecurityNext":   "#3fb950",
            "ScanNetSecurity":"#a371f7",
        }
        c = colors.get(src, "#8b949e")
        return f'<span class="src-badge" style="border-color:{c};color:{c}">{safe(src)}</span>'

    def vuln_rows():
        if not vulns:
            return '<tr><td colspan="5" class="empty">データなし</td></tr>'
        rows = ""
        for r in vulns:
            rows += f"""
      <tr data-sev="{safe(r.get('深刻度',''))}" data-src="{safe(r.get('ソース',''))}">
        <td class="date">{safe(r.get("日付",""))}</td>
        <td>{source_badge(r.get("ソース",""))}</td>
        <td class="title-cell">{linkify(r.get("URL",""), r.get("タイトル",""))}<div class="cve-row">{safe(r.get("CVE",""))}</div></td>
        <td>{sev_badge(r)}</td>
        <td class="desc">{safe(r.get("説明",""))}</td>
      </tr>"""
        return rows

    def news_rows():
        if not news:
            return '<tr><td colspan="4" class="empty">データなし</td></tr>'
        rows = ""
        for r in news:
            rows += f"""
      <tr data-src="{safe(r.get('ソース',''))}">
        <td class="date">{safe(r.get("日付",""))}</td>
        <td>{source_badge(r.get("ソース",""))}</td>
        <td class="title-cell">{linkify(r.get("URL",""), r.get("タイトル",""))}</td>
        <td class="desc">{safe(r.get("説明",""))}</td>
      </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JP Security Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=JetBrains+Mono:wght@500&display=swap');
:root{{
  --bg:#0d1117;--s1:#161b22;--s2:#21262d;--bd:#30363d;
  --tx:#e6edf3;--muted:#8b949e;
  --blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#f0883e;--yellow:#d29922;--purple:#a371f7;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Noto Sans JP',sans-serif;background:var(--bg);color:var(--tx);padding:20px;font-size:13px}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline}}

header{{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px;padding-bottom:20px;border-bottom:1px solid var(--bd);margin-bottom:20px}}
.title h1{{font-size:20px;font-weight:700}}
.title h1 em{{color:var(--blue);font-style:normal}}
.title p{{font-size:12px;color:var(--muted);margin-top:4px;font-family:'JetBrains Mono',monospace}}
.stats{{display:flex;gap:12px;flex-wrap:wrap}}
.stat{{background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:10px 16px;text-align:center;min-width:80px}}
.stat .n{{font-size:26px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}}
.stat .l{{font-size:10px;color:var(--muted);margin-top:3px}}
.stat.danger .n{{color:var(--red)}}
.stat.warn   .n{{color:var(--orange)}}
.stat.info   .n{{color:var(--blue)}}

/* タブ */
.tabs{{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--bd);}}
.tab{{background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);padding:10px 20px;font-size:14px;font-family:inherit;cursor:pointer;font-weight:600;margin-bottom:-1px;}}
.tab:hover{{color:var(--tx)}}
.tab.active{{color:var(--tx);border-bottom-color:var(--blue);}}
.tab .cnt{{font-size:11px;background:var(--s2);border:1px solid var(--bd);border-radius:20px;padding:1px 7px;margin-left:6px;font-weight:400;font-family:'JetBrains Mono',monospace;}}
.tab.active .cnt{{background:rgba(88,166,255,.15);border-color:var(--blue);color:var(--blue);}}

section{{display:none}}
section.active{{display:block}}

.filter-bar{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}}
.filter-bar input{{background:var(--s1);border:1px solid var(--bd);color:var(--tx);padding:6px 12px;border-radius:6px;font-size:13px;width:260px;outline:none;font-family:inherit}}
.filter-bar input:focus{{border-color:var(--blue)}}
.filter-bar input::placeholder{{color:var(--muted)}}
.fbtn{{background:var(--s1);border:1px solid var(--bd);color:var(--muted);padding:5px 12px;border-radius:6px;font-size:11px;font-family:inherit;cursor:pointer;white-space:nowrap}}
.fbtn:hover{{background:var(--s2);color:var(--tx)}}
.fbtn.active{{border-color:var(--blue);color:var(--blue);background:rgba(88,166,255,.1)}}

.wrap{{overflow-x:auto;border:1px solid var(--bd);border-radius:10px}}
table{{width:100%;border-collapse:collapse}}
thead tr{{background:var(--s2)}}
th{{padding:9px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.5px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--bd);white-space:nowrap}}
td{{padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:top;line-height:1.6}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(255,255,255,.02)}}

.date{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);white-space:nowrap}}
.title-cell{{max-width:340px}}
.title-cell a{{font-weight:600}}
.cve-row{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);margin-top:3px}}
.desc{{font-size:12px;color:var(--muted);max-width:300px}}
.empty{{text-align:center;padding:40px;color:var(--muted)}}
.na{{color:var(--muted)}}

.sev-badge{{display:inline-block;border:1px solid;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:600;font-family:'JetBrains Mono',monospace;white-space:nowrap}}
.src-badge{{display:inline-block;border:1px solid;border-radius:20px;padding:2px 9px;font-size:10px;font-weight:600;white-space:nowrap}}

footer{{margin-top:20px;padding-top:14px;border-top:1px solid var(--bd);font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px}}
</style>
</head>
<body>

<header>
  <div class="title">
    <h1>🛡️ <em>JP</em> Security Dashboard</h1>
    <p>JVN / JPCERT/CC / IPA / SecurityNext ― 日本関連セキュリティ情報</p>
  </div>
  <div class="stats">
    <div class="stat danger"><div class="n">{high_count}</div><div class="l">高深刻度</div></div>
    <div class="stat warn"><div class="n">{len(vulns)}</div><div class="l">脆弱性</div></div>
    <div class="stat info"><div class="n">{len(news)}</div><div class="l">ニュース</div></div>
  </div>
</header>

<!-- タブ -->
<div class="tabs">
  <button class="tab active" onclick="switchTab('vuln',this)">⚠️ 脆弱性情報 <span class="cnt">{len(vulns)}</span></button>
  <button class="tab" onclick="switchTab('news',this)">📰 ニュース <span class="cnt">{len(news)}</span></button>
</div>

<!-- 脆弱性タブ -->
<section id="tab-vuln" class="active">
  <div class="filter-bar">
    <input id="vq" type="text" placeholder="🔍 タイトル・CVE・製品名で絞り込み…" oninput="filterVuln()">
    <button class="fbtn active" data-sev="" onclick="setSevFilter(this)">すべて</button>
    <button class="fbtn" data-sev="Critical" onclick="setSevFilter(this)">🔴 Critical</button>
    <button class="fbtn" data-sev="High" onclick="setSevFilter(this)">🟠 High</button>
    <button class="fbtn" data-sev="Medium" onclick="setSevFilter(this)">🟡 Medium</button>
  </div>
  <div class="wrap">
  <table id="vuln-table">
    <thead><tr>
      <th>日付</th><th>ソース</th><th>タイトル / CVE</th><th>深刻度</th><th>概要</th>
    </tr></thead>
    <tbody>{vuln_rows()}</tbody>
  </table>
  </div>
</section>

<!-- ニュースタブ -->
<section id="tab-news">
  <div class="filter-bar">
    <input id="nq" type="text" placeholder="🔍 タイトル・キーワードで絞り込み…" oninput="filterNews()">
  </div>
  <div class="wrap">
  <table id="news-table">
    <thead><tr>
      <th>日付</th><th>ソース</th><th>タイトル</th><th>概要</th>
    </tr></thead>
    <tbody>{news_rows()}</tbody>
  </table>
  </div>
</section>

<footer>
  <span>最終更新: {now_str}</span>
  <span>情報源: JVN iPedia / JPCERT/CC / IPA / SecurityNext</span>
</footer>

<script>
function switchTab(name, btn) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}}

let sevFilter = '';

function setSevFilter(btn) {{
  sevFilter = btn.dataset.sev;
  document.querySelectorAll('.fbtn[data-sev]').forEach(b => b.classList.toggle('active', b === btn));
  filterVuln();
}}

function filterVuln() {{
  const q = document.getElementById('vq').value.toLowerCase();
  document.querySelectorAll('#vuln-table tbody tr').forEach(row => {{
    const txt      = row.textContent.toLowerCase();
    const sev      = row.dataset.sev || '';
    const matchQ   = !q || txt.includes(q);
    const matchSev = !sevFilter || sev.includes(sevFilter);
    row.style.display = (matchQ && matchSev) ? '' : 'none';
  }});
}}

function filterNews() {{
  const q = document.getElementById('nq').value.toLowerCase();
  document.querySelectorAll('#news-table tbody tr').forEach(row => {{
    row.style.display = (!q || row.textContent.toLowerCase().includes(q)) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"HTML生成: {HTML_FILE} ({len(all_records)}件)")

# ── メイン ────────────────────────────────────────────────
def main():
    log("=" * 60)
    log("JP Security Monitor 開始")
    log("=" * 60)

    seen = load_seen()
    raw  = []

    # 脆弱性ソース
    raw.extend(fetch_jvndb())
    time.sleep(1)
    raw.extend(fetch_rdf(
        "https://jvn.jp/rss/jvn.rdf", "JVN", "脆弱性"))
    time.sleep(1)
    raw.extend(fetch_rdf(
        "https://www.jpcert.or.jp/rss/jpcert.rdf", "JPCERT 注意喚起", "脆弱性"))
    time.sleep(1)
    raw.extend(fetch_rdf(
        "https://www.ipa.go.jp/security/rss/alert.rdf", "IPA 脆弱性", "脆弱性"))
    time.sleep(1)

    # ニュースソース
    raw.extend(fetch_security_next())

    log(f"取得合計: {len(raw)}件（フィルター前）")

    # 直近90日に絞り込む
    cutoff = (datetime.now(JST) - timedelta(days=90)).strftime("%Y-%m-%d")
    raw = [r for r in raw if r.get("日付","") >= cutoff or r.get("日付","") == ""]
    log(f"90日以内: {len(raw)}件")

    # 新着のみ抽出
    new_records = []
    for rec in raw:
        uid = make_id(rec["カテゴリ"], rec["ソース"], rec["URL"])
        if uid not in seen:
            new_records.append(rec)
            seen.add(uid)

    log(f"新着: {len(new_records)}件")
    if new_records:
        save_seen(seen)

    # HTML は常に全件で再生成（seen.json から全 URL を取得できないため raw を使用）
    generate_html(raw)
    log("完了\n")

if __name__ == "__main__":
    main()

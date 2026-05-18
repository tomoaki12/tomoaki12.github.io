"""
jp_ransomware_monitor.py
========================
ransomware.live / ransomlook.io から日本関連の被害情報を収集し、
Claude AI で企業情報を自動調査して CSV + HTML レポートを出力する。

【出力①】被害組織情報
  - 組織名、URL、所在地、ランサムウェアグループ
  - 事業内容、資本金、従業員数
  - リークサイトのスクリーンショット画像URL

【出力②】日本の関連組織（親会社・子会社・日本法人）
  - 組織名、URL、所在地、事業内容、資本金、従業員数

必要ライブラリ:
    python3 -m pip install requests beautifulsoup4

環境変数（.envファイル）:
    ANTHROPIC_API_KEY=sk-ant-xxxxx

使い方:
    python3 jp_ransomware_monitor.py
"""

import csv, json, os, re, sys, time
from datetime import datetime, timezone, timedelta

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from pathlib import Path
from urllib.parse import quote_plus

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("python3 -m pip install requests beautifulsoup4 を実行してください")
    sys.exit(1)

# ── 設定 ──────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
CSV_FILE    = BASE_DIR / "jp_ransomware_report.csv"
HTML_FILE   = BASE_DIR / "index.html"
SEEN_FILE   = BASE_DIR / "jp_ransomware_seen.json"
LOG_FILE    = BASE_DIR / "jp_ransomware_monitor.log"
ENV_FILE    = BASE_DIR / ".env"
JST         = timezone(timedelta(hours=9))

def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
}

# CSV列定義
CSV_FIELDS_1 = [
    # ① 被害組織
    "掲載日", "情報源", "攻撃グループ",
    "被害組織名", "被害組織URL", "被害組織_所在地",
    "被害組織_事業内容", "被害組織_資本金", "被害組織_従業員数",
    "スクリーンショットURL", "リークページURL",
]
CSV_FIELDS_2 = [
    # ② 日本関連組織
    "日本関連_有無", "日本関連_関係",
    "日本関連_組織名", "日本関連_URL", "日本関連_所在地",
    "日本関連_事業内容", "日本関連_資本金", "日本関連_従業員数",
]
CSV_FIELDS = CSV_FIELDS_1 + CSV_FIELDS_2 + ["調査日時"]

JAPAN_KEYWORDS = [
    ".co.jp", ".ne.jp", ".or.jp", ".go.jp", ".ac.jp",
    "japan", "japanese", "tokyo", "osaka", "kyoto", "nagoya",
    "yokohama", "sapporo", "fukuoka", "kobe", "kawasaki",
    "株式会社", "有限会社", "合同会社",
]

# ── ユーティリティ ─────────────────────────────────────
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

def make_id(name, group, source):
    return f"{source}|{group}|{name}".lower().strip()

def is_japan(text):
    t = text.lower()
    return any(k.lower() in t for k in JAPAN_KEYWORDS)

def append_csv(records):
    mode = "a" if CSV_FILE.exists() else "w"
    with open(CSV_FILE, mode, newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if mode == "w":
            w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, "") for k in CSV_FIELDS})

def new_session():
    s = requests.Session()
    s.headers.update(HEADERS)
    return s

# ── ransomware.live 取得 ──────────────────────────────
def fetch_ransomware_live():
    results = []
    s = new_session()
    try:
        s.get("https://www.ransomware.live/", timeout=10)
        time.sleep(1)
    except Exception:
        pass

    # API試行 — victims/JP は必ず取得、recentvictims は補完用
    seen_ids = set()

    def parse_items(data, jp_only=False):
        for item in data:
            if not isinstance(item, dict):
                continue
            country = (item.get("country") or "").upper()
            name    = item.get("victim") or item.get("name", "")
            desc    = item.get("description") or ""
            if jp_only:
                pass  # victims/JP は全件JP確定
            else:
                if country != "JP" and not is_japan(name + " " + desc):
                    continue
            uid = item.get("id", "")
            if uid and uid in seen_ids:
                continue
            if uid:
                seen_ids.add(uid)
            screenshot = (
                item.get("screenshot") or
                item.get("image") or
                item.get("img") or
                (f"https://www.ransomware.live/screenshots/{uid}.png" if uid else "")
            )
            results.append({
                "掲載日":       item.get("published") or item.get("discovered", ""),
                "情報源":       "ransomware.live",
                "攻撃グループ": item.get("group") or item.get("gang", ""),
                "被害組織名":   name,
                "被害概要_raw": desc[:500],
                "リークページURL": f"https://www.ransomware.live/id/{uid}" if uid else "https://www.ransomware.live/map/JP",
                "スクリーンショットURL": screenshot,
            })

    # victims/JP を必ず取得（Japanタグ付き全件）
    try:
        r = s.get("https://api.ransomware.live/victims/JP", timeout=20)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                parse_items(data, jp_only=True)
                log(f"ransomware.live victims/JP: {len(results)}件")
    except Exception as e:
        log(f"ransomware.live victims/JP エラー: {e}")

    # recentvictims で補完（victims/JP に含まれない新着を拾う）
    try:
        r = s.get("https://api.ransomware.live/recentvictims", timeout=20)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                before = len(results)
                parse_items(data, jp_only=False)
                log(f"ransomware.live recentvictims 補完: +{len(results)-before}件")
    except Exception as e:
        log(f"ransomware.live recentvictims エラー: {e}")

    if results:
        log(f"ransomware.live API 合計: {len(results)}件（JP関連）")
        return results

    # HTML スクレイピング — /map/JP（国タグあり）とトップページ（最近の被害）を両方取得
    def scrape_html_page(url, jp_only=False):
        try:
            r = s.get(url, timeout=30)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            count = 0
            for card in soup.find_all(True):
                vlink = card.find("a", href=lambda h: h and "/id/" in h)
                if not vlink:
                    continue
                vname = vlink.get_text(strip=True)
                href  = vlink.get("href", "")
                uid   = href.split("/id/")[-1] if "/id/" in href else ""
                if not vname or uid in seen_ids:
                    continue
                # JP判定（トップページは説明文も確認）
                card_text = card.get_text(" ")
                if not jp_only and not is_japan(vname + " " + card_text):
                    continue
                if uid:
                    seen_ids.add(uid)
                glink = card.find("a", href=lambda h: h and "/group/" in h)
                gname = glink.get_text(strip=True) if glink else ""
                m     = re.search(r"(\d{4}-\d{2}-\d{2})", card_text)
                disc  = m.group(1) if m else ""
                img   = card.find("img")
                screenshot = img["src"] if img and img.get("src") else ""
                results.append({
                    "掲載日": disc, "情報源": "ransomware.live",
                    "攻撃グループ": gname, "被害組織名": vname,
                    "被害概要_raw": "",
                    "リークページURL": f"https://www.ransomware.live{href}" if href.startswith("/") else href,
                    "スクリーンショットURL": screenshot,
                })
                count += 1
            return count
        except Exception as e:
            log(f"ransomware.live HTMLエラー ({url}): {e}")
            return 0

    log("ransomware.live: HTMLスクレイピング")
    # /map/JP — 国タグがJPのもの（全件）
    n1 = scrape_html_page("https://www.ransomware.live/map/JP", jp_only=True)
    log(f"ransomware.live /map/JP: {n1}件")
    time.sleep(1)
    # トップページ — 最近の被害（国タグなしでも日本関連を拾う）
    n2 = scrape_html_page("https://www.ransomware.live/", jp_only=False)
    log(f"ransomware.live トップページ補完: +{n2}件")
    log(f"ransomware.live HTML 合計: {len(results)}件")
    return results

# ── ransomlook.io 取得 ────────────────────────────────
def fetch_ransomlook():
    results = []
    s = new_session()
    try:
        s.get("https://www.ransomlook.io/", timeout=10)
        time.sleep(1)
    except Exception:
        pass

    for url in ["https://www.ransomlook.io/api/recent",
                "https://www.ransomlook.io/api/last"]:
        try:
            r = s.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                if not isinstance(data, list) or len(data) == 0:
                    continue
                for item in data:
                    title = item.get("post_title") or item.get("title", "")
                    desc  = item.get("description", "")
                    if not is_japan(title + " " + desc):
                        continue
                    screenshot = item.get("screen") or item.get("screenshot") or item.get("image") or ""
                    results.append({
                        "掲載日":       item.get("discovered") or item.get("date", ""),
                        "情報源":       "ransomlook.io",
                        "攻撃グループ": item.get("group_name") or item.get("group", ""),
                        "被害組織名":   title,
                        "被害概要_raw": desc[:500],
                        "リークページURL": "https://www.ransomlook.io/recent",
                        "スクリーンショットURL": screenshot,
                    })
                log(f"ransomlook.io API: {len(results)}件（JP関連）")
                return results
        except Exception:
            pass

    log("ransomlook.io: HTMLスクレイピング")
    try:
        r = s.get("https://www.ransomlook.io/recent", timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        for row in soup.select("table tr"):
            cols = row.find_all("td")
            if len(cols) < 2:
                continue
            victim = cols[1].get_text(strip=True)
            if not is_japan(victim):
                continue
            img = row.find("img")
            screenshot = img["src"] if img and img.get("src") else ""
            results.append({
                "掲載日": cols[0].get_text(strip=True),
                "情報源": "ransomlook.io",
                "攻撃グループ": cols[2].get_text(strip=True) if len(cols) > 2 else "",
                "被害組織名": victim,
                "被害概要_raw": "",
                "リークページURL": "https://www.ransomlook.io/recent",
                "スクリーンショットURL": screenshot,
            })
        log(f"ransomlook.io HTML: {len(results)}件（JP関連）")
    except Exception as e:
        log(f"ransomlook.io エラー: {e}")
    return results

# ── Claude AI 企業情報調査 ────────────────────────────
CLAUDE_PROMPT = """
以下のランサムウェア被害組織について調査し、JSONのみで回答してください（コードブロック不要）。

組織名: {name}
攻撃グループ: {group}
被害概要: {desc}

回答形式:
{{
  "被害組織URL": "公式サイトURL、不明なら空文字",
  "被害組織_所在地": "本社住所、例: 東京都千代田区 / 米国テキサス州ダラス",
  "被害組織_事業内容": "主要事業（150字以内）",
  "被害組織_資本金": "例: 1億円 / 上場（時価総額〇〇億円） / 不明",
  "被害組織_従業員数": "例: 約1,200名 / 不明",
  "日本関連_有無": "あり または なし",
  "日本関連_関係": "日本企業 / 日本法人（親: 〇〇） / 親会社が日本企業（〇〇） / 子会社が日本にあり / 日本に主要取引先あり / なし",
  "日本関連_組織名": "日本の関連組織名（なければ空文字）",
  "日本関連_URL": "日本の関連組織の公式URL（なければ空文字）",
  "日本関連_所在地": "日本の関連組織の住所（なければ空文字）",
  "日本関連_事業内容": "日本の関連組織の事業内容（なければ空文字）",
  "日本関連_資本金": "日本の関連組織の資本金（なければ空文字）",
  "日本関連_従業員数": "日本の関連組織の従業員数（なければ空文字）"
}}
"""

def research_with_claude(name, group, desc):
    if not ANTHROPIC_API_KEY:
        log("ANTHROPIC_API_KEY 未設定 → AI調査スキップ")
        return {}
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 1500,
                "messages": [{
                    "role": "user",
                    "content": CLAUDE_PROMPT.format(name=name, group=group, desc=desc[:300])
                }],
            },
            timeout=60,
        )
        if resp.status_code != 200:
            log(f"Claude API エラー {resp.status_code}")
            return {}
        text = ""
        for block in resp.json().get("content", []):
            if block.get("type") == "text":
                text += block["text"]
        text = re.sub(r"```json\s*", "", text.strip())
        text = re.sub(r"```\s*", "", text)
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception as e:
        log(f"Claude API 例外: {e}")
    return {}

# ── Google検索でプレスリリース確認 ───────────────────
def check_press_release(name, org_url=""):
    s = new_session()
    queries = [
        f"{name} ransomware",
        f"{name} ランサムウェア 公式",
        f"{name} セキュリティインシデント お知らせ",
        f"{name} data breach press release",
    ]
    press_domains = [
        "prtimes.jp", "businesswire.com", "globenewswire.com",
        "newswire.com", "accesswire.com",
    ]
    press_keywords = [
        "press", "release", "プレス", "リリース", "お知らせ",
        "incident", "breach", "attack", "攻撃", "漏洩", "流出",
        "インシデント", "notice", "announcement", "発表",
    ]
    for q in queries:
        try:
            r = s.get(
                f"https://www.google.com/search?q={quote_plus(q)}&num=10&hl=ja",
                timeout=15
            )
            if r.status_code != 200:
                time.sleep(2)
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/url?q="):
                    href = href[7:].split("&")[0]
                if not href.startswith("http"):
                    continue
                title = a.get_text(strip=True).lower()
                hl    = href.lower()
                is_press  = any(d in hl for d in press_domains)
                is_news   = any(kw in title for kw in press_keywords)
                is_own    = bool(org_url) and org_url.replace("https://","").replace("http://","").split("/")[0] in hl
                if is_press or is_news or is_own:
                    return "あり", href
            time.sleep(1.5)
        except Exception:
            time.sleep(2)
    return "なし", ""

# ── HTML レポート生成 ─────────────────────────────────
def generate_html(all_records):
    now_str = datetime.now(JST).strftime("%Y年%m月%d日 %H:%M JST")
    count   = len(all_records)
    related = sum(1 for r in all_records if r.get("日本関連_有無") == "あり")
    groups  = len(set(r.get("攻撃グループ","") for r in all_records if r.get("攻撃グループ","")))

    def safe(v):
        return str(v or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def link(url, text=None):
        if not url or url in ("不明",""):
            return "—"
        label = safe(text or url)
        return f'<a href="{safe(url)}" target="_blank" rel="noopener">{label}</a>'

    def screenshot_cell(url):
        if not url:
            return '<span class="na">—</span>'
        return f'<a href="{safe(url)}" target="_blank" rel="noopener"><img src="{safe(url)}" class="thumb" onerror="this.parentElement.innerHTML=\'<span class=na>画像なし</span>\'"></a>'

    def pr_badge(status):
        if status == "あり":
            return '<span class="badge badge-green">✅ あり</span>'
        if status == "なし":
            return '<span class="badge badge-red">❌ なし</span>'
        return '<span class="badge badge-gray">— 未調査</span>'

    def related_section(r):
        if r.get("日本関連_有無") != "あり":
            return '<span class="na">なし</span>'
        return f"""
        <div class="related-block">
          <div class="related-rel">{safe(r.get("日本関連_関係",""))}</div>
          <div class="related-name">{link(r.get("日本関連_URL",""), r.get("日本関連_組織名",""))}</div>
          <div class="related-detail">
            📍 {safe(r.get("日本関連_所在地","—"))}<br>
            💼 {safe(r.get("日本関連_事業内容","—"))}<br>
            💴 資本金: {safe(r.get("日本関連_資本金","—"))}<br>
            👥 従業員: {safe(r.get("日本関連_従業員数","—"))}
          </div>
        </div>"""

    rows = ""
    for r in all_records:
        rows += f"""
      <tr>
        <td class="date">{safe(r.get("掲載日",""))}</td>
        <td>
          <div class="org-name">{safe(r.get("被害組織名",""))}</div>
          <div class="org-url">{link(r.get("被害組織URL",""))}</div>
          <div class="org-loc">📍 {safe(r.get("被害組織_所在地","—"))}</div>
        </td>
        <td><span class="group-badge">{safe(r.get("攻撃グループ",""))}</span><br>
            <span class="source">{safe(r.get("情報源",""))}</span></td>
        <td class="biz">{safe(r.get("被害組織_事業内容","—"))}</td>
        <td class="num">{safe(r.get("被害組織_資本金","—"))}</td>
        <td class="num">{safe(r.get("被害組織_従業員数","—"))}</td>
        <td class="ss">{screenshot_cell(r.get("スクリーンショットURL",""))}<br>
            {link(r.get("リークページURL",""), "🔗 詳細")}</td>
        <td>{related_section(r)}</td>
      </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JP Ransomware Monitor</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700&family=JetBrains+Mono:wght@500&display=swap');
:root{{
  --bg:#0d1117;--s1:#161b22;--s2:#21262d;--bd:#30363d;
  --tx:#e6edf3;--muted:#8b949e;
  --acc:#f0883e;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Noto Sans JP',sans-serif;background:var(--bg);color:var(--tx);padding:20px;font-size:13px}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline}}

/* ヘッダー */
header{{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px;padding-bottom:20px;border-bottom:1px solid var(--bd);margin-bottom:20px}}
.title h1{{font-size:20px;font-weight:700}}
.title h1 em{{color:var(--acc);font-style:normal}}
.title p{{font-size:12px;color:var(--muted);margin-top:4px;font-family:'JetBrains Mono',monospace}}
.stats{{display:flex;gap:12px;flex-wrap:wrap}}
.stat{{background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:10px 16px;text-align:center;min-width:80px}}
.stat .n{{font-size:26px;font-weight:700;color:var(--acc);font-family:'JetBrains Mono',monospace;line-height:1}}
.stat .l{{font-size:10px;color:var(--muted);margin-top:3px}}

/* フィルター */
.filter{{margin-bottom:14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.filter input{{background:var(--s1);border:1px solid var(--bd);color:var(--tx);padding:7px 12px;border-radius:6px;font-size:13px;width:280px;outline:none;font-family:inherit}}
.filter input:focus{{border-color:var(--blue)}}
.filter input::placeholder{{color:var(--muted)}}
.filter select{{background:var(--s1);border:1px solid var(--bd);color:var(--tx);padding:7px 12px;border-radius:6px;font-size:13px;outline:none}}
.filter-btn{{background:var(--s1);border:1px solid var(--bd);color:var(--muted);padding:7px 14px;border-radius:6px;font-size:12px;font-family:inherit;cursor:pointer;white-space:nowrap}}
.filter-btn:hover{{background:var(--s2);color:var(--tx)}}
.filter-btn.active{{border-color:var(--blue);color:var(--blue);background:rgba(88,166,255,.1)}}

/* テーブル */
.wrap{{overflow-x:auto;border:1px solid var(--bd);border-radius:10px}}
table{{width:100%;border-collapse:collapse}}
thead tr{{background:var(--s2)}}
th{{padding:10px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.5px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--bd);white-space:nowrap}}
td{{padding:11px 12px;border-bottom:1px solid var(--bd);vertical-align:top;line-height:1.6}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(255,255,255,.02)}}

/* セル */
.date{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted);white-space:nowrap}}
.org-name{{font-weight:700;font-size:14px;margin-bottom:2px}}
.org-url{{font-size:11px;word-break:break-all}}
.org-loc{{font-size:11px;color:var(--muted);margin-top:3px}}
.group-badge{{display:inline-block;background:var(--s2);border:1px solid var(--bd);border-radius:20px;padding:2px 10px;font-size:11px;font-weight:600;color:var(--acc);white-space:nowrap}}
.source{{font-size:10px;color:var(--muted);margin-top:4px;display:block}}
.biz{{max-width:200px;font-size:12px;color:var(--muted)}}
.num{{font-family:'JetBrains Mono',monospace;font-size:12px;white-space:nowrap}}
.ss{{text-align:center}}
.thumb{{width:120px;height:75px;object-fit:cover;border-radius:4px;border:1px solid var(--bd);display:block;margin-bottom:4px}}
.na{{color:var(--muted);font-size:12px}}

/* 日本関連 */
.related-block{{background:rgba(88,166,255,.06);border:1px solid rgba(88,166,255,.2);border-radius:6px;padding:8px 10px}}
.related-rel{{font-size:10px;color:var(--blue);font-weight:600;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}}
.related-name{{font-weight:700;font-size:13px;margin-bottom:6px}}
.related-detail{{font-size:11px;color:var(--muted);line-height:1.8}}

/* バッジ */
.badge{{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}}
.badge-green{{color:var(--green)}}
.badge-red{{color:var(--red)}}
.badge-gray{{color:var(--muted)}}

/* フッター */
footer{{margin-top:20px;padding-top:14px;border-top:1px solid var(--bd);font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px}}
</style>
</head>
<body>
<header>
  <div class="title">
    <h1>🔴 <em>JP</em> Ransomware Monitor</h1>
    <p>ransomware.live / ransomlook.io ― 日本関連被害追跡レポート</p>
  </div>
  <div class="stats">
    <div class="stat"><div class="n">{count}</div><div class="l">総件数</div></div>
    <div class="stat"><div class="n">{related}</div><div class="l">日本関連あり</div></div>
    <div class="stat"><div class="n">{groups}</div><div class="l">攻撃グループ</div></div>
  </div>
</header>

<div class="filter">
  <input id="q" type="text" placeholder="🔍 組織名・グループ・事業内容で絞り込み…" oninput="filt()">
  <button class="filter-btn active" data-filter="" onclick="setFilter(this)">すべて</button>
  <button class="filter-btn" data-filter="confirmed" onclick="setFilter(this)">🇯🇵 日本タグあり</button>
  <button class="filter-btn" data-filter="possible" onclick="setFilter(this)">⚠️ 日本関係の可能性あり</button>
  <button class="filter-btn" data-filter="none" onclick="setFilter(this)">不明</button>
</div>

<div class="wrap">
<table id="t">
  <thead>
    <tr>
      <th class="sortable" onclick="sortTable(0)" style="cursor:pointer">掲載日 <span id="sort0">▼</span></th>
      <th>① 被害組織 / URL / 所在地</th>
      <th>グループ / 情報源</th>
      <th>事業内容</th>
      <th>資本金</th>
      <th>従業員数</th>
      <th>スクショ / リンク</th>
      <th>② 日本の関連組織</th>
    </tr>
  </thead>
  <tbody id="tb">{rows if rows else '<tr><td colspan="8" style="text-align:center;padding:50px;color:var(--muted)">データなし</td></tr>'}</tbody>
</table>
</div>

<footer>
  <span>最終更新: {now_str}</span>
  <span>情報源: ransomware.live / ransomlook.io ― 情報共有目的のみ</span>
</footer>

<script>
let sortDir = -1;
let currentFilter = '';

const JP_PLACE = /tokyo|osaka|kyoto|yokohama|nagoya|sapporo|fukuoka|hiroshima|sendai|aichi|kanagawa|chiba|hokkaido|nippon|musashi|kosugi|kawasaki|kyushu|tohoku/i;

function japanLevel(row) {{
  if (row.cells[7] && row.cells[7].querySelector('.related-block')) return 'confirmed';
  const nameEl = row.querySelector('.org-name');
  const urlEl  = row.querySelector('.org-url');
  const nameText = nameEl ? nameEl.textContent : '';
  const urlText  = urlEl  ? urlEl.textContent  : '';
  if (/\\.(?:co|or|ne|ac|go|ed)\\.jp\\b/i.test(row.innerHTML)) return 'possible';
  if (/[぀-龯]/.test(nameText)) return 'possible';
  if (JP_PLACE.test(nameText + ' ' + urlText)) return 'possible';
  return 'none';
}}

function sortTable(col){{
  sortDir *= -1;
  document.getElementById('sort0').textContent = sortDir === -1 ? '▼' : '▲';
  const tb = document.getElementById('tb');
  const rows = Array.from(tb.querySelectorAll('tr'));
  rows.sort((a, b) => {{
    const va = a.cells[col] ? a.cells[col].textContent.trim() : '';
    const vb = b.cells[col] ? b.cells[col].textContent.trim() : '';
    return va < vb ? sortDir : va > vb ? -sortDir : 0;
  }});
  rows.forEach(r => tb.appendChild(r));
}}

function setFilter(btn) {{
  currentFilter = btn.dataset.filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b === btn));
  filt();
}}

function filt(){{
  const q = document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#tb tr').forEach(row => {{
    const txt = row.textContent.toLowerCase();
    const matchQ      = !q || txt.includes(q);
    const matchFilter = !currentFilter || japanLevel(row) === currentFilter;
    row.style.display = (matchQ && matchFilter) ? '' : 'none';
  }});
}}

window.onload = () => {{
  sortTable(0);
  document.querySelectorAll('#tb tr').forEach(row => {{
    const sourceEl = row.querySelector('.source');
    const detailLink = Array.from(row.querySelectorAll('.ss a')).find(a => a.textContent.includes('詳細'));
    if (sourceEl && detailLink) {{
      const a = document.createElement('a');
      a.href = detailLink.href;
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = sourceEl.textContent;
      sourceEl.textContent = '';
      sourceEl.appendChild(a);
    }}
  }});
}};
</script>
</body>
</html>"""

    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"HTMLレポート生成: {HTML_FILE}")

# ── メイン ────────────────────────────────────────────
def main():
    log("=" * 60)
    log("JP Ransomware Monitor 開始")
    log("=" * 60)

    seen    = load_seen()
    now_str = datetime.now(JST).strftime("%Y-%m-%d %H:%M:%S")

    # 1. 両サイトから取得
    raw = []
    raw.extend(fetch_ransomware_live())
    time.sleep(2)
    raw.extend(fetch_ransomlook())
    log(f"取得合計: {len(raw)}件（日本関連）")

    # 1b. 2026年4月以降のみに絞り込み
    FILTER_FROM = "2026-04"
    filtered = []
    for rec in raw:
        date = rec.get("掲載日", "")
        if date >= FILTER_FROM:
            filtered.append(rec)
        else:
            log(f"  スキップ（{date}）: {rec.get('被害組織名','')}")
    log(f"2026-04以降: {len(filtered)}件")
    raw = filtered

    # 2. 新着のみ
    new_raw = []
    for rec in raw:
        rid = make_id(rec["被害組織名"], rec["攻撃グループ"], rec["情報源"])
        if rid not in seen:
            new_raw.append(rec)
            seen.add(rid)
    log(f"新着: {len(new_raw)}件")

    # 3. CSV行組み立て（企業調査・プレスリリース確認はスキップ）
    new_records = []
    for i, rec in enumerate(new_raw, 1):
        name  = rec["被害組織名"]
        group = rec.get("攻撃グループ", "")
        log(f"  [{i}/{len(new_raw)}] 追加: {name}")

        new_records.append({
            "調査日時":          now_str,
            "掲載日":            rec.get("掲載日",""),
            "情報源":            rec.get("情報源",""),
            "攻撃グループ":      group,
            "被害組織名":        name,
            "被害組織URL":       "不明",
            "被害組織_所在地":   "不明",
            "被害組織_事業内容": "不明",
            "被害組織_資本金":   "不明",
            "被害組織_従業員数": "不明",
            "スクリーンショットURL": rec.get("スクリーンショットURL",""),
            "リークページURL":   rec.get("リークページURL",""),
            "日本関連_有無":     "不明",
            "日本関連_関係":     "",
            "日本関連_組織名":   "",
            "日本関連_URL":      "",
            "日本関連_所在地":   "",
            "日本関連_事業内容": "",
            "日本関連_資本金":   "",
            "日本関連_従業員数": "",
        })

    # 4. 保存
    if new_records:
        append_csv(new_records)
        save_seen(seen)
        log(f"★ 新着 {len(new_records)}件 → CSV保存")

    # 5. HTML再生成（全履歴）
    all_records = []
    if CSV_FILE.exists():
        with open(CSV_FILE, encoding="utf-8-sig") as f:
            all_records = list(csv.DictReader(f))
    generate_html(all_records)

    # 6. サマリー表示
    if new_records:
        print()
        print("=" * 65)
        print(f"  新着 {len(new_records)} 件")
        print("=" * 65)
        for r in new_records:
            jp = "🔴 日本関連あり" if r["日本関連_有無"] == "あり" else "⚪ 関連なし"
            print(f"  {r['掲載日']:12s}  {r['被害組織名']}  ({r['攻撃グループ']})")
            print(f"              {jp}  {r.get('日本関連_関係','')}")
        print("=" * 65)
        print(f"\n  CSV  : {CSV_FILE}")
        print(f"  HTML : {HTML_FILE}")
    else:
        log("新着なし")

    log("完了\n")

if __name__ == "__main__":
    main()

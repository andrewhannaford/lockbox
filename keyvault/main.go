// Command keyvault is a minimal self-hosted secret store for backing up your own keys.
//
// It stores named secrets encrypted at rest with AES-256-GCM (key from MASTER_KEY).
// Access control is handled by the reverse proxy (Pocket ID / OIDC), not by this service.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed lockbox.py
var lockboxPy []byte

var (
	masterKey   []byte
	dataDir     string
	payloadsDir string
	apiKey      string

	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

	uiHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeyVault</title>
<style>
:root{--bg:#0a0c10;--surface:#10141a;--border:#1e2530;--border-hover:#2d3748;--text:#cdd5e0;--text-dim:#5a6478;--accent:#4f8ef7;--green:#3fb950;--red:#f85149;--red-dim:rgba(248,81,73,0.08);--radius:8px;--mono:"SFMono-Regular","Cascadia Code",Consolas,monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;min-height:100vh}
.shell{max-width:900px;margin:0 auto;padding:0 24px 64px}
.topbar{display:flex;align-items:center;border-bottom:1px solid var(--border);margin-bottom:32px;padding-top:20px}
.topbar-brand{font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text-dim);padding-right:24px;border-right:1px solid var(--border);margin-right:4px;white-space:nowrap}
.nav-link{display:inline-flex;align-items:center;gap:6px;padding:10px 16px;font-size:13px;font-weight:500;color:var(--text-dim);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s,border-color .15s}
.nav-link:hover{color:var(--text)}.nav-link.active{color:var(--accent);border-bottom-color:var(--accent)}
.nav-icon{width:14px;height:14px;opacity:.7}
.page-header{margin-bottom:24px}.page-title{font-size:22px;font-weight:600}
.section-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-dim);margin-bottom:10px}
.key-row{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 16px;margin-bottom:8px;transition:border-color .12s}
.key-row:hover{border-color:var(--border-hover)}
.key-name{font-weight:600;font-family:var(--mono);font-size:13px;flex:1;cursor:pointer;word-break:break-all}.key-name:hover{color:var(--accent)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:500;border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;font-family:inherit;transition:background .12s,border-color .12s;white-space:nowrap}
.btn:hover{background:rgba(255,255,255,0.05);border-color:var(--border-hover)}
.btn-del{color:var(--red);border-color:rgba(248,81,73,0.3)}.btn-del:hover{background:var(--red-dim);border-color:var(--red)}
.value{margin:-2px 0 8px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:12px;color:var(--text);word-break:break-all;white-space:pre-wrap}
.hint{color:var(--text-dim);font-size:13px;padding:8px 0}
</style></head><body>
<div class="shell">
<div class="topbar">
<span class="topbar-brand">KeyVault</span>
<a href="/" class="nav-link active"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a3 3 0 0 0-3 3v1H3a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2V4a3 3 0 0 0-3-3zm1 5H7V4a1 1 0 1 1 2 0v2z"/></svg>Keys</a>
<a href="/payloads" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M7.47 10.78a.75.75 0 0 0 1.06 0l3.75-3.75a.75.75 0 0 0-1.06-1.06L8.75 8.44V1.75a.75.75 0 0 0-1.5 0v6.69L4.78 5.97a.75.75 0 0 0-1.06 1.06l3.75 3.75zM1.75 13.5a.75.75 0 0 0 0 1.5h12.5a.75.75 0 0 0 0-1.5H1.75z"/></svg>Payloads</a>
<a href="/guide" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 2.828c.885-.37 2.154-.769 3.388-.893 1.33-.134 2.458.063 3.112.752v9.746c-.935-.53-2.12-.603-3.213-.493-1.18.12-2.37.461-3.287.811V2.828zm7.5-.141v9.746c.935-.53 2.12-.603 3.213-.493 1.18.12 2.37.461 3.287.811V2.828c-.885-.37-2.154-.769-3.388-.893-1.33-.134-2.458.063-3.112.752zM8 1.783C7.015.936 5.587.81 4.287.94c-1.514.153-3.042.672-3.994 1.105A.5.5 0 0 0 0 2.5v11a.5.5 0 0 0 .707.455c.882-.4 2.303-.881 3.68-1.02 1.409-.142 2.59.087 3.223.877a.5.5 0 0 0 .78 0c.633-.79 1.814-1.019 3.222-.877 1.378.139 2.8.62 3.681 1.02A.5.5 0 0 0 16 13.5v-11a.5.5 0 0 0-.293-.455c-.952-.433-2.48-.952-3.994-1.105C10.413.809 8.985.936 8 1.783z"/></svg>Guide</a>
</div>
<div class="page-header"><h1 class="page-title">Keys</h1></div>
<div class="section-label">Backed-up keys</div>
<div id="list"></div>
</div>
<script>
function h(){return {'Content-Type':'application/json'};}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
async function load(){
  var box=document.getElementById('list');
  var r=await fetch('/keys',{headers:h()}); var d=await r.json();
  if(r.status!==200){box.innerHTML='<p class="hint">'+esc(JSON.stringify(d))+'</p>';return;}
  var keys=d.keys||[];
  if(!keys.length){box.innerHTML='<p class="hint">No keys yet. Run Lockbox with --vault to back one up.</p>';return;}
  box.innerHTML='';
  keys.forEach(function(k){
    var row=document.createElement('div'); row.className='key-row';
    var n=document.createElement('span'); n.className='key-name'; n.textContent=k.name; n.title='Click to reveal'; n.onclick=function(){show(k.name);};
    var hh=document.createElement('span'); hh.className='hint'; hh.textContent=k.host||'(unknown host)';
    var b=document.createElement('button'); b.className='btn btn-del'; b.textContent='Delete'; b.onclick=function(){del(k.name);};
    row.appendChild(n); row.appendChild(hh); row.appendChild(b); box.appendChild(row);
  });
}
async function show(name){
  var box=document.getElementById('list');
  var r=await fetch('/keys/'+encodeURIComponent(name),{headers:h()}); var d=await r.json();
  var v=document.createElement('div'); v.className='value';
  v.textContent=(d.host?'host: '+d.host+'\n':'')+(d.value!==undefined?d.value:JSON.stringify(d));
  box.appendChild(v);
}
async function del(name){
  if(!confirm('Delete key "'+name+'"?')) return;
  await fetch('/keys/'+encodeURIComponent(name),{method:'DELETE',headers:h()}); load();
}
load();
</script></body></html>`

	payloadsHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeyVault - Payloads</title>
<style>
:root{--bg:#0a0c10;--surface:#10141a;--border:#1e2530;--border-hover:#2d3748;--text:#cdd5e0;--text-dim:#5a6478;--accent:#4f8ef7;--radius:8px;--mono:"SFMono-Regular","Cascadia Code",Consolas,monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;min-height:100vh}
.shell{max-width:900px;margin:0 auto;padding:0 24px 64px}
.topbar{display:flex;align-items:center;border-bottom:1px solid var(--border);margin-bottom:32px;padding-top:20px}
.topbar-brand{font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text-dim);padding-right:24px;border-right:1px solid var(--border);margin-right:4px;white-space:nowrap}
.nav-link{display:inline-flex;align-items:center;gap:6px;padding:10px 16px;font-size:13px;font-weight:500;color:var(--text-dim);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s,border-color .15s}
.nav-link:hover{color:var(--text)}.nav-link.active{color:var(--accent);border-bottom-color:var(--accent)}
.nav-icon{width:14px;height:14px;opacity:.7}
.page-header{margin-bottom:24px}.page-title{font-size:22px;font-weight:600}
.section-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-dim);margin-bottom:10px}
.key-row{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 16px;margin-bottom:8px}
.key-name{font-weight:600;font-family:var(--mono);font-size:13px;flex:1;word-break:break-all;color:var(--accent);text-decoration:none}.key-name:hover{text-decoration:underline}
.value{margin:0 0 8px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:12px;color:var(--text);white-space:pre-wrap}
.hint{color:var(--text-dim);font-size:13px}
</style></head><body>
<div class="shell">
<div class="topbar">
<span class="topbar-brand">KeyVault</span>
<a href="/" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a3 3 0 0 0-3 3v1H3a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2V4a3 3 0 0 0-3-3zm1 5H7V4a1 1 0 1 1 2 0v2z"/></svg>Keys</a>
<a href="/payloads" class="nav-link active"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M7.47 10.78a.75.75 0 0 0 1.06 0l3.75-3.75a.75.75 0 0 0-1.06-1.06L8.75 8.44V1.75a.75.75 0 0 0-1.5 0v6.69L4.78 5.97a.75.75 0 0 0-1.06 1.06l3.75 3.75zM1.75 13.5a.75.75 0 0 0 0 1.5h12.5a.75.75 0 0 0 0-1.5H1.75z"/></svg>Payloads</a>
<a href="/guide" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 2.828c.885-.37 2.154-.769 3.388-.893 1.33-.134 2.458.063 3.112.752v9.746c-.935-.53-2.12-.603-3.213-.493-1.18.12-2.37.461-3.287.811V2.828zm7.5-.141v9.746c.935-.53 2.12-.603 3.213-.493 1.18.12 2.37.461 3.287.811V2.828c-.885-.37-2.154-.769-3.388-.893-1.33-.134-2.458.063-3.112.752zM8 1.783C7.015.936 5.587.81 4.287.94c-1.514.153-3.042.672-3.994 1.105A.5.5 0 0 0 0 2.5v11a.5.5 0 0 0 .707.455c.882-.4 2.303-.881 3.68-1.02 1.409-.142 2.59.087 3.223.877a.5.5 0 0 0 .78 0c.633-.79 1.814-1.019 3.222-.877 1.378.139 2.8.62 3.681 1.02A.5.5 0 0 0 16 13.5v-11a.5.5 0 0 0-.293-.455c-.952-.433-2.48-.952-3.994-1.105C10.413.809 8.985.936 8 1.783z"/></svg>Guide</a>
</div>
<div class="page-header"><h1 class="page-title">Payloads</h1></div>
<p class="hint">The Lockbox executables and the Python script.</p>
<div class="section-label">Windows</div>
<div class="key-row"><a href="/payloads/lockbox.exe" download class="key-name">lockbox.exe</a><span class="hint">Windows executable</span></div>
<div class="section-label" style="margin-top:20px">Linux</div>
<div class="key-row"><a href="/payloads/lockbox" download class="key-name">lockbox</a><span class="hint">Linux executable · chmod +x after download</span></div>
<div class="section-label" style="margin-top:20px">Script</div>
<div class="key-row"><a href="/lockbox.py" download class="key-name">lockbox.py</a><span class="hint">Python 3 · AES-256-GCM</span></div>
<div class="section-label" style="margin-top:20px">Usage</div>
<div class="value">lockbox.exe encrypt secret.txt --key-file key.txt --vault https://keyvault.lanarchy.net --backup-name my-key
lockbox.exe decrypt secret.txt.lockbox --key-file key.txt</div>
</div>
</body></html>`

	guideHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeyVault - Guide</title>
<style>
:root{--bg:#0a0c10;--surface:#10141a;--border:#1e2530;--border-hover:#2d3748;--text:#cdd5e0;--text-dim:#5a6478;--accent:#4f8ef7;--radius:8px;--mono:"SFMono-Regular","Cascadia Code",Consolas,monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;min-height:100vh}
.shell{max-width:900px;margin:0 auto;padding:0 24px 64px}
.topbar{display:flex;align-items:center;border-bottom:1px solid var(--border);margin-bottom:32px;padding-top:20px}
.topbar-brand{font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text-dim);padding-right:24px;border-right:1px solid var(--border);margin-right:4px;white-space:nowrap}
.nav-link{display:inline-flex;align-items:center;gap:6px;padding:10px 16px;font-size:13px;font-weight:500;color:var(--text-dim);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s,border-color .15s}
.nav-link:hover{color:var(--text)}.nav-link.active{color:var(--accent);border-bottom-color:var(--accent)}
.nav-icon{width:14px;height:14px;opacity:.7}
.page-header{margin-bottom:24px}.page-title{font-size:22px;font-weight:600}
.section-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-dim);margin-bottom:10px}
.hint{color:var(--text-dim);font-size:13px;padding:8px 0}
h2{font-size:16px;font-weight:600;margin:28px 0 10px;color:var(--text)}
p{line-height:1.6;margin:8px 0}
code{font-family:var(--mono);font-size:12px;background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:1px 5px}
pre{margin:10px 0 18px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:12px;color:var(--text);overflow-x:auto;white-space:pre}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
ul{margin:10px 0 18px;padding-left:22px;line-height:1.7}
li{margin:4px 0}
table{border-collapse:collapse;width:100%;margin:12px 0 20px;font-size:13px}
th,td{text-align:left;padding:8px 12px;border:1px solid var(--border);vertical-align:top}
th{color:var(--text-dim);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
</style></head><body>
<div class="shell">
<div class="topbar">
<span class="topbar-brand">KeyVault</span>
<a href="/" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a3 3 0 0 0-3 3v1H3a1 1 0 0 0-1 1v7a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2V4a3 3 0 0 0-3-3zm1 5H7V4a1 1 0 1 1 2 0v2z"/></svg>Keys</a>
<a href="/payloads" class="nav-link"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M7.47 10.78a.75.75 0 0 0 1.06 0l3.75-3.75a.75.75 0 0 0-1.06-1.06L8.75 8.44V1.75a.75.75 0 0 0-1.5 0v6.69L4.78 5.97a.75.75 0 0 0-1.06 1.06l3.75 3.75zM1.75 13.5a.75.75 0 0 0 0 1.5h12.5a.75.75 0 0 0 0-1.5H1.75z"/></svg>Payloads</a>
<a href="/guide" class="nav-link active"><svg class="nav-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1 2.828c.885-.37 2.154-.769 3.388-.893 1.33-.134 2.458.063 3.112.752v9.746c-.935-.53-2.12-.603-3.213-.493-1.18.12-2.37.461-3.287.811V2.828zm7.5-.141v9.746c.935-.53 2.12-.603 3.213-.493 1.18.12 2.37.461 3.287.811V2.828c-.885-.37-2.154-.769-3.388-.893-1.33-.134-2.458.063-3.112.752zM8 1.783C7.015.936 5.587.81 4.287.94c-1.514.153-3.042.672-3.994 1.105A.5.5 0 0 0 0 2.5v11a.5.5 0 0 0 .707.455c.882-.4 2.303-.881 3.68-1.02 1.409-.142 2.59.087 3.223.877a.5.5 0 0 0 .78 0c.633-.79 1.814-1.019 3.222-.877 1.378.139 2.8.62 3.681 1.02A.5.5 0 0 0 16 13.5v-11a.5.5 0 0 0-.293-.455c-.952-.433-2.48-.952-3.994-1.105C10.413.809 8.985.936 8 1.783z"/></svg>Guide</a>
</div>
<div class="page-header"><h1 class="page-title">Guide</h1></div>
<p>Lockbox encrypts files and folders with AES-256-GCM. Only someone with your passphrase or key file can decrypt them. KeyVault is the companion service that backs up the keys you generate.</p>

<h2>Get the tool</h2>
<ul>
<li><a href="/payloads/lockbox.exe">lockbox.exe</a> — Windows executable.</li>
<li><a href="/payloads/lockbox">lockbox</a> — Linux executable.</li>
<li><a href="/lockbox.py">lockbox.py</a> — the same tool as a Python 3 script.</li>
</ul>

<h2>Encrypt and decrypt</h2>
<p>With a passphrase (you'll be prompted):</p>
<pre>lockbox.exe encrypt secret.txt
lockbox.exe decrypt secret.txt.lockbox</pre>
<p>With a key file:</p>
<pre>lockbox.exe encrypt secret.txt --key-file key.bin --delete
lockbox.exe decrypt secret.txt.lockbox --key-file key.bin</pre>
<ul>
<li><code>encrypt &lt;dir&gt;</code> encrypts every file inside it, writing a <code>.lockbox</code> sibling for each.</li>
<li><code>--delete</code> removes the original after encrypting (and the <code>.lockbox</code> after decrypting).</li>
<li>A wrong passphrase or key fails safely — the original is never modified.</li>
</ul>

<h2>Secure your user folders</h2>
<pre>lockbox.exe secure</pre>
<p>Encrypts <code>Documents</code>, <code>Desktop</code>, <code>Downloads</code>, <code>Pictures</code>, <code>Videos</code>, and <code>Music</code>. Defaults to a passphrase; add <code>--key-file</code> or <code>--vault</code> for a generated key.</p>

<h2>Key backup (KeyVault)</h2>
<pre>lockbox.exe encrypt secret.txt --vault https://keyvault.lanarchy.net --backup-name my-key</pre>
<ul>
<li>The key is generated randomly and stored here, encrypted at rest, so you can decrypt later without remembering it.</li>
<li>Only requests carrying the shared API key can upload keys. That key is baked into the executable at build time.</li>
<li>Each backed-up key is labeled with the hostname of the machine it came from — see the <a href="/">Keys</a> page.</li>
</ul>

<h2>Building the executable</h2>
<pre>pip install cryptography pyinstaller
python build_exe.py</pre>
<p><code>build_exe.py</code> generates a fresh API key, bakes it into the exe, and prints it. Set that same value as <code>API_KEY</code> in the KeyVault service environment.</p>

<h2>Security notes</h2>
<ul>
<li>Store your passphrase or key file somewhere separate from the encrypted data.</li>
<li>If you lose the passphrase and the key backup, the data is unrecoverable — by design.</li>
<li>Keep KeyVault's <code>MASTER_KEY</code> and <code>API_KEY</code> safe; <code>MASTER_KEY</code> decrypts every stored key.</li>
</ul>
</div>
</body></html>`
)

func main() {
	key, err := hex.DecodeString(os.Getenv("MASTER_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("MASTER_KEY must be a 64-char hex string (32 bytes)")
	}
	masterKey = key
	dataDir = os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	payloadsDir = os.Getenv("PAYLOADS_DIR")
	if payloadsDir == "" {
		payloadsDir = "/payloads"
	}
	apiKey = os.Getenv("API_KEY")
	if apiKey == "" {
		log.Printf("API_KEY not set; POST /keys will be rejected")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/payloads", handlePayloads)
	mux.HandleFunc("/payloads/", handlePayloadFile)
	mux.HandleFunc("/lockbox.py", handleLockboxPy)
	mux.HandleFunc("/guide", handleGuide)
	mux.HandleFunc("/", handleUI)
	mux.HandleFunc("/keys", handleKeys)
	mux.HandleFunc("/keys/", handleKey)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("keyvault listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(uiHTML))
}

func handlePayloads(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(payloadsHTML))
}

func handleGuide(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(guideHTML))
}

func handlePayloadFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/payloads/")
	if !validName(name) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(payloadsDir, name))
}

func handleLockboxPy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-python; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="lockbox.py"`)
	w.Write(lockboxPy)
}

func handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := listKeys()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"keys": keys})
	case http.MethodPost:
		if !validAPIKey(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Host  string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if !validName(body.Name) {
			http.Error(w, "name must match [A-Za-z0-9._-]{1,128}", http.StatusBadRequest)
			return
		}
		if body.Value == "" {
			http.Error(w, "value must not be empty", http.StatusBadRequest)
			return
		}
		raw, err := json.Marshal(map[string]string{"value": body.Value, "host": body.Host})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		enc, err := encrypt(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(keyPath(body.Name), enc, 0o600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"stored": body.Name})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleKey(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/keys/")
	if !validName(name) {
		http.Error(w, "invalid key name", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(keyPath(name))
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		plain, err := decrypt(data)
		if err != nil {
			http.Error(w, "decryption failed", http.StatusInternalServerError)
			return
		}
		host, value := splitPayload(plain)
		writeJSON(w, map[string]string{"name": name, "host": host, "value": value})
	case http.MethodDelete:
		if err := os.Remove(keyPath(name)); err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"deleted": name})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func keyPath(name string) string {
	return filepath.Join(dataDir, name+".enc")
}

type keyMeta struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

func listKeys() ([]keyMeta, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, err
	}
	keys := []keyMeta{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		meta := keyMeta{Name: strings.TrimSuffix(e.Name(), ".enc")}
		if data, err := os.ReadFile(filepath.Join(dataDir, e.Name())); err == nil {
			if plain, err := decrypt(data); err == nil {
				meta.Host, _ = splitPayload(plain)
			}
		}
		keys = append(keys, meta)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys, nil
}

func validName(name string) bool {
	return nameRe.MatchString(name)
}

func validAPIKey(r *http.Request) bool {
	if apiKey == "" {
		return false
	}
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	return subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) == 1
}

func splitPayload(plain []byte) (host, value string) {
	var p struct {
		Host  string `json:"host"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(plain, &p); err != nil || p.Value == "" {
		return "", string(plain)
	}
	return p.Host, p.Value
}

func encrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

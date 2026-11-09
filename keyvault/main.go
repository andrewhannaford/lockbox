// Command keyvault is a minimal self-hosted secret store for backing up your own keys.
//
// It stores named secrets encrypted at rest with AES-256-GCM (key from MASTER_KEY).
// Access control is handled by the reverse proxy (Pocket ID / OIDC), not by this service.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	masterKey []byte
	dataDir   string
	payloadsDir string

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
    var n=document.createElement('span'); n.className='key-name'; n.textContent=k; n.title='Click to reveal'; n.onclick=function(){show(k);};
    var b=document.createElement('button'); b.className='btn btn-del'; b.textContent='Delete'; b.onclick=function(){del(k);};
    row.appendChild(n); row.appendChild(b); box.appendChild(row);
  });
}
async function show(name){
  var box=document.getElementById('list');
  var r=await fetch('/keys/'+encodeURIComponent(name),{headers:h()}); var d=await r.json();
  var v=document.createElement('div'); v.className='value'; v.textContent=(d.value!==undefined?d.value:JSON.stringify(d));
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
</div>
<div class="page-header"><h1 class="page-title">Payloads</h1></div>
<p class="hint">The Lockbox executable and the Python script.</p>
<div class="section-label">Executable</div>
<div class="key-row"><a href="/payloads/lockbox.exe" download class="key-name">lockbox.exe</a><span class="hint">Windows</span></div>
<div class="section-label" style="margin-top:20px">Script</div>
<div class="key-row"><a href="/lockbox.py" download class="key-name">lockbox.py</a><span class="hint">Python 3 · AES-256-GCM</span></div>
<div class="section-label" style="margin-top:20px">Usage</div>
<div class="value">lockbox.exe encrypt secret.txt --key-file key.txt --vault https://keyvault.lanarchy.net --backup-name my-key
lockbox.exe decrypt secret.txt.lockbox --key-file key.txt</div>
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
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/payloads", handlePayloads)
	mux.HandleFunc("/payloads/", handlePayloadFile)
	mux.HandleFunc("/lockbox.py", handleLockboxPy)
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

func handlePayloadFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/payloads/")
	if !validName(name) || !strings.HasSuffix(strings.ToLower(name), ".exe") {
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
		names, err := listNames()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"keys": names})
	case http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Value string `json:"value"`
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
		enc, err := encrypt([]byte(body.Value))
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
		writeJSON(w, map[string]string{"name": name, "value": string(plain)})
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

func listNames() ([]string, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".enc"))
	}
	sort.Strings(names)
	return names, nil
}

func validName(name string) bool {
	return nameRe.MatchString(name)
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

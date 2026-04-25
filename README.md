

Extensie a pipeline-ului care rulează detecția de atacuri web în timp real, fără a mai necesita colectarea și analiza post-factum a logurilor. Sistemul citește logurile Nginx pe măsură ce acestea sunt generate și emite alerte imediat ce identifică un request suspect.

> **Precondiție obligatorie:** Acest branch necesită modelele antrenate în branch-ul de analiză. Fișierele `exp5a_tuned_iso.pkl`, `exp5a_tuned_rf.pkl` și `exp5a_tuned_le.pkl` trebuie să existe în directorul proiectului înainte de a rula detectorul.

---

## Cerințe de Sistem

- **Docker Desktop** — orchestrarea serviciilor Web (Nginx), Backend (PHP) și Security (OWASP ZAP)
- **Miniconda / Anaconda** — mediul de execuție Machine Learning
- **PowerShell** — automatizarea traficului legitim
- **Modele antrenate** — `exp5a_tuned_iso.pkl`, `exp5a_tuned_rf.pkl`, `exp5a_tuned_le.pkl`

---

## 1. Configurare Mediu Python

```powershell
conda create -n mllogs python=3.10 -y
conda activate mllogs
conda install pandas scikit-learn matplotlib -y
```

---

## 2. Infrastructură

Proiectul rulează în aceeași rețea izolată cu trei componente principale:

- **web-server** — Nginx configurat cu formatul de logare detaliat, expus pe portul `8080`
- **php** — backend-ul PHP-FPM care procesează cererile aplicației
- **zap-scanner** — scannerul de securitate care simulează atacurile

```bash
docker-compose up -d
```

Nginx folosește un format de log personalizat (`detailed`) care include IP, timestamp, request, status, bytes, user-agent, request time și query args — toate câmpurile necesare pentru extragerea features-urilor în timp real.

---

## 3. Generarea Traficului

Generarea logurilor urmează același flux ca în branch-ul de phpapp. Logurile se numesc `dataset_train_v2.log` și `dataset_test_v2.log`.

### Log de Antrenament (`dataset_train_v2.log`)

```powershell
# Trafic normal
powershell -ExecutionPolicy Bypass -File normal_traffic.ps1

# Baseline-ul
docker exec website-zap-scanner-1 zap-baseline.py -t http://web-server

# Atacuri — se rulează de 3 ori
docker exec website-zap-scanner-1 zap-full-scan.py -t http://web-server

# Extragere log
docker logs website-web-server-1 > dataset_train_v2.log
```

### Log de Testare (`dataset_test_v2.log`)

```powershell
# Trafic normal
powershell -ExecutionPolicy Bypass -File normal_traffic.ps1

# Baseline-ul
docker exec website-zap-scanner-1 zap-baseline.py -t http://web-server

# Extragere log
docker logs website-web-server-1 > dataset_test_v2.log
```

> **Notă:** Logurile sunt incluse în repository. Pașii de mai sus sunt necesari doar dacă se dorește generarea unor loguri noi.

---

## 4. Detecție în Timp Real

Scriptul `realtime_detector.py` procesează logurile Nginx linie cu linie pe măsură ce sunt scrise, combinând trei straturi de detecție:

- **Isolation Forest** — scor de anomalie per request bazat pe features textuale
- **Random Forest** — clasificare multiclasă pentru identificarea tipului de atac
- **Sliding window per IP** — detectează comportament suspect pe baza ratei de request, proporției de erori și diversității de path-uri în ultimele N secunde

Alertele sunt afișate în timp real în terminal cu timestamp, IP sursă, tip de atac, path accesat și scorul ISO. Dacă un IP depășește pragurile comportamentale (>60 req/min, >50% erori HTTP, >20 path-uri unice sau >30% anomalii în fereastră), alerta este marcată suplimentar cu `[SCAN]`.

### Mod 1 — Tail direct pe containerul Docker

```powershell
python realtime_detector.py --docker website-web-server-1 --model exp5a_tuned
```

### Mod 2 — Tail pe fișier local

```powershell
python realtime_detector.py --log /path/to/access.log --model exp5a_tuned
```

### Mod 3 — Simulare pe log existent 

```powershell
python realtime_detector.py --log dataset_test_v2.log --model exp5a_tuned --simulate
```

---

## 5. Opțiuni Complete

| Argument | Tip | Default | Descriere |
|---|---|---|---|
| `--log` | `str` | — | Calea către fișierul de log Nginx |
| `--docker` | `str` | — | Numele containerului Docker (`docker logs --follow`) |
| `--model` | `str` | `exp5a_tuned` | Prefixul modelelor `.pkl` |
| `--window` | `int` | `60` | Dimensiunea sliding window per IP (secunde) |
| `--threshold` | `float` | `None` | Threshold manual ISO (dacă nu e setat, folosește decizia nativă a modelului) |
| `--output` | `str` | — | Fișier JSON pentru salvarea alertelor |
| `--simulate` | flag | `False` | Rulează pe fișier existent cu delay simulat |
| `--delay` | `float` | `0.005` | Delay între linii în modul simulate (secunde) |
| `--no-color` | flag | `False` | Dezactivează culorile ANSI în terminal |

Exemplu cu toate opțiunile relevante:

```powershell
python realtime_detector.py --docker website-web-server-1 --model exp5a_tuned --window 120 --threshold 0.476 --output alerte.json
```

---

## 6. Format Output

Fiecare alertă afișată în terminal urmează formatul:

```
HH:MM:SS          IP.ADDR  [   ATTACK_TYPE]  METHOD  /path/accesat              score=0.XXX
                            payload: <primii 80 de caractere din payload>
```

Dacă IP-ul este marcat ca suspect de sliding window:
```
HH:MM:SS          IP.ADDR  [   ATTACK_TYPE]  METHOD  /path/accesat              score=0.XXX [SCAN: 72req/min, 15 anomalii]
```

La fiecare 30 de secunde și la oprire (Ctrl+C), sunt afișate statistici agregate:

```
  Total: N requesturi | Anomalii: M (X.X%)
          sqli: ...
          recon: ...
  IP-uri active: K | Suspecte: J
```

Dacă este specificat `--output`, toate alertele sunt salvate în format JSON la oprirea detectorului.

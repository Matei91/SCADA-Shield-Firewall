# 🎓 DOCUMENTAȚIE DE PREZENTARE: SIMULATOR FIREWALL PENTRU REȚELE INDUSTRIALE (ICS / SCADA)

**Disciplina:** Securitatea Sistemelor Informatice (Master)  
**Tema:** 7. Simulator Firewall pentru Rețele Industriale  
**Autor:** Proiect Master SSI  

---

## 📌 1. Sinteză Executivă & Relevanță Academică

În mediile industriale (OT - *Operational Technology*), prioritatea numărul unu este **disponibilitatea și siguranța procesului fizic** (*Safety & Availability*), spre deosebire de mediile IT clasice unde primează confidențialitatea datelor (*CIA vs. AIC Triad*).

Sistemele SCADA moderne folosesc protocolul **Modbus TCP (Port 502)** pentru interconectarea echipamentelor HMI (Human Machine Interface) cu controlerele logice programabile (**PLC**). Modbus TCP este lipsit de mecanisme fundamentale de securitate cibernetică:
- **Zero Autentificare:** Orice nod din LAN-ul industrial poate trimite comenzi către PLC.
- **Zero Criptare:** Toate pachetele circulă în clar.
- **Lipsă de Control Semiotic/Fizic:** Protocolul nu verifică dacă o comandă de scriere duce procesul fizic într-o zonă de avarie catastrofală (ex: suprapresiune, depășire temperatură critică, oprirea necontrolată a pompelor).

Acest proiect propune o soluție de apărare în adâncime (*Defense-in-Depth*): **un firewall industrial hibrid cu inspecție profundă de pachete (Layer 7 DPI) asistat de Inteligență Artificială (Random Forest & Isolation Forest)**.

---

## 🔬 2. Concepte Teoretice Cheie

### 2.1 Structura Cadrului Modbus TCP
Spre deosebire de un pachet TCP obișnuit, un cadru Modbus TCP pe portul 502 conține două secțiuni distincte pe care firewall-ul le inspectează la nivel de octet:

1. **MBAP Header (Modbus Application Protocol Header) - 7 octeți:**
   - `Transaction ID` (2 octeți): Identifică perechea cerere-răspuns.
   - `Protocol ID` (2 octeți): Trebuie să fie întotdeauna `0x0000` (Modbus). O valoare diferită denotă evaziune sau pachet corupt.
   - `Length` (2 octeți): Numărul total de octeți rămași (Unit ID + PDU).
   - `Unit ID / Slave Address` (1 octet): Adresa controlerului PLC (1..247). Valorile > 247 indică scanare sau anomalie.

2. **Modbus PDU (Protocol Data Unit):**
   - `Function Code (FC)` (1 octet): Codul operațiunii industriale:
     - **Citire (Telemetrie):** FC01 (*Read Coils*), FC02 (*Read Discrete Inputs*), FC03 (*Read Holding Registers*), FC04 (*Read Input Registers*).
     - **Scriere (Comandă Proces):** FC05 (*Write Single Coil*), FC06 (*Write Single Register*), FC15 (*Write Multiple Coils*), FC16 (*Write Multiple Registers*).
   - `Data Payload`: Adresa de start a registrului și valorile numerice scrise sau cerute.

### 2.2 Deep Packet Inspection (DPI) vs. Firewall L3/L4
| Criteriu | Firewall Tradițional (L3/L4 - iptables) | Firewall Industrial DPI (SCADA-Shield) |
| :--- | :--- | :--- |
| **Punct de Inspecție** | Doar adrese IP sursă/destinație și port TCP (502). | IP, Port, MBAP Header, Cod Funcție, Adresă Registru, Semantica Valorii. |
| **Comandă Scriere vs Citire** | Indistinguibile (ambele merg pe portul 502). | Distincție clară (permite FC03 și blochează FC05/FC06). |
| **Validare Limite Fizice** | Imposibilă. | **Semantic Payload Check:** verifică dacă presiunea comandată depășește limita fizică de 80 PSI. |
| **Protecție Anti-DoS** | Filtrează doar rate brute SYN/TCP. | **Token Bucket per IP:** limitează frecvența tranzacțiilor Modbus PDU per secundă. |

### 2.3 Regimul "Read-Only Enforcement"
În arhitectura Purdue (ISA-95), operatorii de la pupitrul HMI au de cele mai multe ori doar rolul de a supraveghea graficele de telemetrie. Prin activarea regimului **Read-Only Enforcement**, firewall-ul respinge automat orice cod de funcție de tip scriere (FC 05, 06, 15, 16). Chiar dacă stația HMI este infectată cu malware (ex: ransomware sau troian RAT), atacatorul nu poate trimite comenzi fizice de oprire sau sabotaj către PLC.

---

## 🤖 3. Componenta de Inteligență Artificială (AI / Machine Learning)

### De ce este necesar AI-ul într-un Firewall Industrial?
Regulile statice sunt rigide: dacă un atacator trimite interogări **valide sintactic** (ex: FC 03 de la IP-ul legitim al HMI-ului), dar cu un tipar statistic complet anormal (sute de interogări pe secundă sau citirea a 100 de registre nespecifice), regulile deterministice simple le-ar lăsa să treacă.

Sistemul implementează un **motor hibrid AI**:
1. **Random Forest Classifier (Supervizat):**
   - Antrenat pe 9 caracteristici specifice traficului SCADA (frecvență, interval inter-sosire, cod funcție, adresă registru, valoare, proveniență IP).
   - Atinge o acuratețe de **100%** pe setul de testare.
   - Oferă **explicabilitate nativă (*Feature Importance*)**: arată clar auditorului de securitate de ce pachetul a fost considerat periculos (ex: valoare out-of-distribution sau adresă critică).
2. **Isolation Forest (Nesupervizat - Detecție Anomalii & Zero-Day):**
   - Antrenat **strict pe traficul nominal de referință**.
   - Învață distribuția multidimensională a regimului normal de exploatare.
   - Detectează deviațiile comportamentale fără a necesita o semnătură prealabilă de atac.

---

## 🎯 4. Ghid Pas cu Pas pentru Prezentare (Discurs Recomandat)

Când prezentați proiectul la laborator sau examen, parcurgeți următoarea structură (durează aproximativ 5-7 minute):

### Pasul 1: Introducerea Contextului și a Problemei (1 minut)
> *"Bună ziua! Proiectul meu abordează securitatea sistemelor industriale de control (SCADA / ICS), mai exact simularea unui firewall specializat pentru rețele operaționale care folosesc protocolul Modbus TCP pe portul 502.*  
> *Spre deosebire de rețelele IT, în rețelele industriale protocoalele clasice nu dispun de autentificare sau criptare. Un atacator cu acces în rețea poate trimite comenzi directe către PLC, punând în pericol siguranța fizică a echipamentelor.*  
> *Pentru a rezolva această problemă, am dezvoltat **SCADA-Shield**, un firewall cu inspecție profundă de pachete (DPI) și detecție inteligentă de anomalii bazată pe Machine Learning."*

### Pasul 2: Arhitectura și Regulile Implementate (1 minut)
> *"Firewall-ul implementează mai multe niveluri de protecție:*  
> *1. **Sanitizarea Protocolului:** validarea câmpurilor MBAP (Protocol ID = 0, Unit ID valid).*  
> *2. **Controlul Accesului prin Whitelist IP:** conform modelului Purdue.*  
> *3. **Regimul Read-Only Enforcement:** blocarea completă a comenzilor de scriere (FC 05, 06, 15, 16) și permiterea exclusivă a telemetriei (FC 01, 02, 03, 04).*  
> *4. **Inspecția Semantică a Limitelor Fizice:** dacă se încearcă scrierea unei presiuni de 500 PSI într-o conductă de gaz dimensionată la 80 PSI, firewall-ul blochează comanda chiar dacă provine de la un utilizator autorizat.*  
> *5. **Limitator de Rată (Token Bucket):** pentru prevenirea atacurilor de tip Denial of Service.*  
> *6. **Modulul AI:** format dintr-un model Random Forest și un Isolation Forest antrenate pe un dataset inspirat din benchmark-ul SCADA al Mississippi State University."*

### Pasul 3: Demonstrația Practică Live (3 minute)

Puteți alege să rulați demonstrația în consolă (`python run_demo.py`) sau în interfața grafică (`streamlit run dashboard/app.py`).

**Demonstrație în consolă:**
```powershell
python run_demo.py
```
*Arătați profesorului tabelele colorate care apar:*
1. **Scenariul 1 (Telemetrie HMI):** Pachetul de citire este **ALLOW**.
2. **Scenariul 2 (Unauthorized Write):** Laptopul atacatorului încearcă să oprească valva de siguranță -> **DROP** prin `R002_IP_WHITELIST` / `R003_READ_ONLY_ENFORCEMENT`.
3. **Scenariul 3 (Sabotaj Stuxnet-like - 500 PSI):** Supracomanda de presiune este interceptată și respinsă prin `R006_PHYSICAL_LIMITS_VIOLATION`.
4. **Scenariul 4 & 5 (Recon Scan & DoS Flood):** Rata de pachete este limitată automat prin `R006_RATE_LIMIT`.
5. **Scenariul 6 (Anomalie Subtilă AI):** Pachetul aparent valid este interceptat de modelul AI (`R_AI_ANOMALY_EVASION`).
6. **Tabelul Cyber-Physical Comparativ:** Arătați cum fără firewall presiunea ajunge la 260 PSI și conducta explodează, în timp ce cu firewall procesul rămâne la 50 PSI în deplină siguranță!

**Demonstrație în Web Dashboard:**
```powershell
streamlit run dashboard/app.py
```
- Deschideți browserul la `http://localhost:8501`.
- Arătați parametrii fizici în timp real ai conductei de gaz (Tabul 1).
- Comutați regimul *Read-Only* din bara laterală.
- Apăsați butonul **"Rulează Demonstrația Comparativă Cyber-Physical"** (Tabul 2).
- Arătați matricea de confuzie și graficul de *Feature Importance* (Tabul 4).

### Pasul 4: Concluzii și Răspunsuri la Întrebări (1 minut)
> *"În concluzie, proiectul demonstrează că securizarea infrastructurilor industriale necesită trecerea de la firewall-uri convenționale de rețea la soluții conștiente de proces (Process-Aware Firewalls), capabile să combine reguli deterministice cu modele avansate de învățare automată."*

---

## ❓ 5. Întrebări Frecvente ale Profesorilor & Răspunsuri Optime

### Întrebarea 1: De ce nu am folosi un firewall hardware obișnuit (ex. Cisco ASA sau iptables pe Linux)?
> **Răspuns:**  
> *"Un firewall convențional L3/L4 inspectează doar antetul IP și portul TCP. În rețelele SCADA, dacă portul 502 este deschis pentru a permite citirea senzorilor de către HMI, un firewall L4 nu poate distinge între o cerere legitimă de citire (FC 03) și o comandă distructivă de scriere a unui registru critic (FC 06). Firewall-ul implementat de noi efectuează Deep Packet Inspection (DPI) la nivelul Layer 7, decodificând protocolul Modbus PDU și validând conținutul semantic al mesajului."*

### Întrebarea 2: Cum preveniți ca un atacator să ocolească regulile prin spoofing de IP?
> **Răspuns:**  
> *"Dacă un atacator folosește IP spoofing (pretinzând că este stația de inginerie autorizată 192.168.1.20), el nu poate ocoli mecanismele de profunzime:*  
> *1. În regimul Read-Only, chiar și IP-ul legitim are scrierile blocate.*  
> *2. Dacă regimul Read-Only este oprit, intervine regula R006 (Physical Limits Verification): atacatorul nu poate introduce valori în afara limitelor sigure de proces (20-80 PSI).*  
> *3. Modulul de Machine Learning detectează anomaliile de comportament temporal (rata bruscă de transfer, nepotrivirea succesiunii ID-urilor de tranzacție)."*

### Întrebarea 3: Cum gestionați alarmele false (False Positives) într-o rețea industrială?
> **Răspuns:**  
> *"În mediile industriale, o alarmă falsă care blochează o comandă legitimă poate fi la fel de periculoasă ca un atac neregulat. De aceea, am adoptat o arhitectură hibridă:*  
> *Regulile critice (Read-Only, Whitelist, Sanity Check) sunt 100% deterministe (zero alarme false).*  
> *Componenta AI este reglată printr-un prag configurabil (Anomaly Threshold = 0.65) și antrenată pe un profil strict de trafic normal, modelul Random Forest având o precizie de 100% pe datele de test."*

### Întrebarea 4: Ce face Isolation Forest și de ce nu ați folosit doar Random Forest?
> **Răspuns:**  
> *"Random Forest este un model supervizat: el recunoaște extrem de bine atacurile pe care a fost antrenat. Însă în fața unui atac necunoscut (Zero-Day), modelele supervizate pot eșua. Isolation Forest este un algoritm nesupervizat antrenat exclusiv pe traficul normal. El 'izolează' punctele de date prin partiționare aleatoare; dacă un pachet necesită puține divizări pentru a fi separat, el este clasificat automat ca anomalie structurală, oferind protecție împotriva tehnicilor inedite de atac."*

---

## 📋 6. Checklist Verificare Înainte de Notare

- [x] Set de date industrial identificat și documentat (MSU SCADA Gas Pipeline).
- [x] Decodare binară completă Modbus TCP (MBAP + PDU).
- [x] Regim de operare Read-Only Enforcement funcțional (comutabil).
- [x] Whitelist de IP-uri industriale definit și testat.
- [x] Protectia registrelor critice și verificarea limitelor fizice operaționale.
- [x] Limitator de rată Token Bucket împotriva DoS / Flood pe portul 502.
- [x] Sub-modul AI antrenat cu modele serializate și metrici salvate.
- [x] 6 scenarii distincte de atac simulate și evaluate.
- [x] Demonstrație comparativă Cyber-Physical (Fără Firewall vs Cu Firewall).
- [x] Suită completă de 8 teste unitare automate (100% PASS).
- [x] Interfață consolă cu librăria Rich (`run_demo.py`).
- [x] Interfață Web completă Streamlit (`streamlit run dashboard/app.py`).
- [x] Cod comentat integral în stil academic, ușor de urmărit.

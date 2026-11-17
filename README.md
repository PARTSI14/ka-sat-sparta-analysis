# KA-SAT (Viasat) 2022 Attack: SPARTA & MITRE ATT&CK Mapping

> Work in progress — portfolio project analysing a real-world space-sector cyber incident with the SPARTA and MITRE ATT&CK frameworks.

## 1. Executive summary

_TODO (5 lines): what happened, who was affected, how, key lesson._

## 2. Attack timeline

| Time (UTC, 24 Feb 2022) | Event | Source |
| --- | --- | --- |
| TODO | Initial access via misconfigured VPN appliance | Viasat |
| TODO | Lateral movement into management segment | Viasat |
| TODO | Mass management commands / AcidRain deployed to modems | Viasat, SentinelLabs |
| TODO | Modems offline across Ukraine and Europe | Viasat |

## 3. SPARTA mapping

| # | Phase | SPARTA technique | Evidence |
| --- | --- | --- | --- |
| 1 | Initial access via VPN | IA-0007 Compromise Ground System | |
| 2 | Lateral movement | PER-0003 Ground System Presence; LM-0007 Credentialed Traversal (by analogy) | Viasat: lateral movement within the trusted management segment |
| 3 | Legitimate-looking commands | IA-0007.02 Malicious Commanding via Valid GS (by analogy) | Viasat: legitimate, targeted management commands sent to many modems simultaneously |
| 4 | User terminals targeted | IA-0009.03 Trusted Relationship: User Segment (partial — reverse direction) | Modems trusted the provider's management plane and executed its commands |
| 5 | AcidRain wiper | IMP-0012 Software, Firmware, or Programmable Logic Manipulation — objective: Disable (by analogy) | SentinelLabs: AcidRain overwrote key data in modem flash memory, rendering devices inoperable |
| 6 | DoS from modems | TODO (Impact) | |

_Navigator layer: `layers/sparta-layer.json` · screenshot: `images/sparta-navigator.png`_

## 4. MITRE ATT&CK mapping

| # | Phase | ATT&CK technique |
| --- | --- | --- |
| 1 | Initial access via VPN | T1133 External Remote Services |
| 2 | Lateral movement | T1021 Remote Services |
| 3 | Mass management commands | T1072 Software Deployment Tools |
| 5 | AcidRain wiper | T1495 Firmware Corruption, T1561 Disk Wipe |
| 6 | DoS from modems | T1498 Network Denial of Service |

_Navigator layer: `layers/attack-layer.json` · screenshot: `images/attack-navigator.png`_

## 5. Detection opportunities (SOC view)

| Phase | What a SOC could have seen |
| --- | --- |
| | |

## 6. Countermeasures

| Phase | SPARTA CM | NIST 800-53 | ISO 27001:2022 |
| --- | --- | --- | --- |
| | | | |

## 7. Open questions & limitations

- No full public forensic report from Viasat.
- TODO
- **SPARTA coverage gap:** IA-0007 (Compromise Ground System) describes ground-segment compromise as a path to the spacecraft. In KA-SAT the initial access matches (VPN → management network), but the satellite itself was never touched; the target was the user terminals. The mapping is therefore by analogy, which is why this analysis also uses MITRE ATT&CK.
- **SPARTA Lateral Movement scope:** SPARTA defines this tactic as movement within a spacecraft or between nodes in a constellation (ST0007). Movement inside a ground network is out of scope, so LM-0007 is applied by analogy and ATT&CK T1021 covers the actual behaviour.
- **DE-0004 Masquerading considered and rejected:** the technique describes forging or imitating an authorized origin. In KA-SAT the commands came from the real (compromised) management system, so only the effect matches, not the method. IA-0007.02 covers this case better.
- **Reverse trust direction:** SPARTA IA-0009.03 describes a compromised user terminal as a springboard *into* the provider and spacecraft. KA-SAT shows the opposite path: a compromised provider management plane used *against* thousands of user terminals that trusted it. This provider-to-customer direction is not explicitly modelled in SPARTA.
- **Dwell time unknown:** Viasat has not disclosed when the attacker first gained access. A pre-positioned foothold, held until 24 Feb, is plausible but unconfirmed.
- **Why destroy instead of persist? (assessment):** the timing suggests the objective was disruption of communications at the start of the invasion, not intelligence collection. A wiper makes the outage last (modems had to be replaced or reflashed) and destroys forensic evidence, at the cost of "burning" the access.
  
## 8. Sources

- [Viasat: KA-SAT Network cyber attack overview](https://www.viasat.com/perspectives/corporate/2022/ka-sat-network-cyber-attack-overview/)
- [SentinelLabs: AcidRain, A Modem Wiper Rains Down on Europe](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/)
- [SPARTA](https://sparta.aerospace.org)
- [MITRE ATT&CK](https://attack.mitre.org)

# PRD - PII Shield

## Vision
Identifier et anonymiser automatiquement les donnees personnelles pour assurer la conformite RGPD.

## Probleme
Les organisations stockent des PII sans visibilite ni controle de traitement.

## Utilisateurs
- DPO / Equipes conformite
- DevSecOps / Data engineering

## MVP (fonctionnalites)
- Detection PII (email, tel, IBAN, IP, carte)
- Anonymisation (mask/hash/token/remove)
- Audit JSON + stats

## Evolutions
- NER/NLP avance
- Integration CI/CD
- Rapport HTML de conformite

## KPI
- PII detectees par flux
- Temps de traitement par enregistrement
- % faux positifs

## Entrees / Sorties
- Entrees: JSON/JSONL
- Sorties: `cleaned.json`, `audit.json`, `stats.json`

## Contraintes
- Execution locale sans dependances lourdes
- Traçabilite RGPD

## Hors perimetre
- DLP temps reel en production

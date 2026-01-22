## Privacy Proxy & Conformite RGPD (PII Shield)

### Objectif
Detecter et anonymiser automatiquement les donnees a caractere personnel (PII) dans les flux, afin d'assurer la conformite RGPD et le "privacy by design".

### Contexte et usage
- Positionnement: proxy entre sources de donnees et applications consommatrices
- Cas d'usage: logs, ETL, API, data lake, exports
- Mode: temps reel et batch

### Fonctionnalites principales
- Detection multi-source (email, telephone, IBAN, adresse, nom, identifiants)
- Anonymisation configurable (masquage, tokenisation, hachage sale, suppression)
- Regles metier par domaine et par type de flux
- Journalisation et traçabilite (preuves de conformite)
- Seuils de risque et blocage automatique

### Architecture (modules)
- Ingestion: connecteurs HTTP, fichiers, messages (ex: Kafka)
- Detection: moteur de regles + modele NER pour PII
- Anonymisation: strategies par type de champ
- Gouvernance: registre de traitements et politiques de retention
- Audit: logs signés et tableaux de bord

### Flux de traitement
1. Capture du flux entrant
2. Normalisation + extraction de champs
3. Detection PII (regles + IA)
4. Anonymisation conforme aux politiques
5. Emission du flux nettoye + audit

### Conformite RGPD
- Minimisation des donnees
- Limitation de finalite
- Droit a l'oubli (retention et purge)
- Pseudonymisation et chiffrement
- Traçabilite des traitements

### Stack proposee
- Python + FastAPI (API)
- spaCy / Presidio (NER PII)
- Redis (tokenisation)
- PostgreSQL (registre, politiques)
- Kafka (streaming)

### Tests et qualite
- Tests unitaires sur regles PII
- Jeux d'essai synthétiques
- Taux de faux positifs/negatifs
- Tests RGPD (retention, effacement, export)

### Livrables
- API de proxy PII
- Registre de traitements
- Tableau de bord de conformite

### Execution
- Exemple simple: `python pii_shield.py`
- Avec fichier: `python pii_shield.py --input data.json --output cleaned.json --audit audit.json`
- Champs cibles: `--fields message,details --mode token`
- Config avancée: `--config config.json --stats stats.json`
- Policies par type: `policies` (mask/hash/token/remove) dans `config.json`
- Demo: `python pii_shield.py --input data.sample.json --config config.sample.json --audit audit.json --stats stats.json`

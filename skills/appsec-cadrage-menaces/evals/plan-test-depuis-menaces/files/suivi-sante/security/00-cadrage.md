# Cadrage et autorisation : suivi-sante

- Niveau ASVS cible : L3 (données de santé)
- Porte G1 : franchie le 2026-11-03 : « OK pour tester mon app en local et sur la preview Vercel (plan Pro), pas la prod »

| Élément | Valeur |
|---|---|
| Stack | React/Vite + Supabase (Auth e-mail, Postgres, Storage, 1 Edge Function `resume-ia` qui appelle un LLM) + Vercel Pro |
| Rôles | patient, soignant, admin ; tenants = cabinets |
| Environnements | labo local (à monter), preview Vercel (staging), prod exclue |

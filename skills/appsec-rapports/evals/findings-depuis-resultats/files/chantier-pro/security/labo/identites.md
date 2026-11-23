# Identités du laboratoire : chantier-pro

Mot de passe commun : `LABO_MOT_DE_PASSE` dans `.env.lab`.

| Identité | Tenant | Rôle | E-mail | UUID |
|---|---|---|---|---|
| anon | aucun | non connecté | | |
| a-admin | A | admin | a-admin@labo.test | `d6f305b4-428b-5ad7-9301-78169d1e5e97` |
| a-membre | A | membre | a-membre@labo.test | `59477c4e-3369-543c-8605-fb60c22a1aa8` |
| a-lecteur | A | lecteur | a-lecteur@labo.test | `4c8cea23-9e72-5674-b9c8-401035030044` |
| b-admin | B | admin | b-admin@labo.test | `173026ef-c121-5b24-a559-983079a75fbe` |
| b-membre | B | membre | b-membre@labo.test | `caec34cd-ebfb-58db-a9cb-4c4a3b3174ba` |
| b-lecteur | B | lecteur | b-lecteur@labo.test | `d3b00025-2c3f-5b75-95a7-62bc50045c4b` |

## Marqueurs de données

| Table | Tenant | Marqueur |
|---|---|---|
| public.accidents | A | `SECRET-TENANT-A-001` |
| public.accidents | A | `SECRET-TENANT-A-002` |
| public.accidents | B | `SECRET-TENANT-B-001` |
| public.accidents | B | `SECRET-TENANT-B-002` |
| storage:photos-accidents | A | `SECRET-TENANT-A-101` |
| storage:photos-accidents | B | `SECRET-TENANT-B-101` |

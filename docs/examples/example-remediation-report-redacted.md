## Exemple de rapport généré

Le script génère un rapport JSON indiquant les actions simulées ou appliquées.

Exemple de rapport en mode simulation :

```markdown
> Les valeurs sensibles comme le nom de machine, le nom d’utilisateur et les chemins locaux complets ont été anonymisées dans cet exemple.
```

```json
{
  "Metadata": {
    "ReportName": "AI Remediation Report",
    "GeneratedAt": "2026-05-11 10:25:40",
    "Version": "V2.3",
    "ApplyMode": false,
    "NonDestructiveByDefault": true,
    "OutputPath": ".\\result\\ai_remediation_report_YYYY-MM-DD_HH-mm-ss.json"
  },
  "SystemInfo": {
    "ComputerName": "REDACTED-HOSTNAME",
    "UserName": "REDACTED-USER",
    "PowerShellVersion": "7.6.1",
    "StartedAt": "2026-05-11 10:25:38",
    "EndedAt": "2026-05-11 10:25:40"
  },
  "Options": {
    "DisableWindowsAITasks": true,
    "CleanChromeAICache": true,
    "CleanOfficeAugLoop": true
  },
  "Summary": {
    "TotalActions": 24,
    "Errors": 0,
    "Mode": "DryRun"
  },
  "Actions": [
    {
      "Category": "policy_hardening",
      "Action": "VerifyPolicy",
      "Target": "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\GenAILocalFoundationalModelSettings",
      "Mode": "Check",
      "Status": "Present",
      "Message": "Politique protectrice présente avec valeur 1"
    },
    {
      "Category": "windows_ai_task",
      "Action": "DisableScheduledTask",
      "Target": "\\Microsoft\\Windows\\WindowsAI\\ClickToDo\\ModelCachingIdle",
      "Mode": "DryRun",
      "Status": "WouldDisable",
      "Message": "La tâche serait désactivée avec -Apply"
    },
    {
      "Category": "browser_ai_cache",
      "Action": "RemovePath",
      "Target": "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\optimization_guide_model_store",
      "Mode": "DryRun",
      "Status": "WouldRemove",
      "Message": "Nettoyage du cache Chrome optimization_guide_model_store"
    },
    {
      "Category": "office_ai_resource",
      "Action": "RemovePath",
      "Target": "%USERPROFILE%\\AppData\\Local\\Microsoft\\AugLoop",
      "Mode": "DryRun",
      "Status": "WouldRemove",
      "Message": "Nettoyage du cache Microsoft AugLoop"
    }
  ],
  "Errors": []
}
```
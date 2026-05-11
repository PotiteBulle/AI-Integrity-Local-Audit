# AI-Integrity-Local-Audit
Installation puis mise à jour de Windows dans une VM afin de tester un nouveau script PowerShell permettant de vérifier la présence de composants IA dans un environnement Windows fraîchement installé.

## Résumé

- Total findings : 43
- Risk score : 74
- Hardening score : 34
- Legacy weighted score : 127
- Risk level : Élevé
- Confirmed AI components : 3
- Windows AI features : 5
- Policy hardening findings : 17
- Policy gaps : 0
- Local model candidates : 0
- Browser AI caches : 16
- Office AI resources : 2
- Reality check : Présence IA Windows confirmée.

## Synthèse par catégorie

-  : 43

## Résultats détaillés

### aimgr

- Category : confirmed_ai_component
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Paquet Appx Windows lié à l’écosystème IA Microsoft
- RelativePath : %ProgramFiles%\WindowsApps\aimgr_0.20.47.0_x64__8wekyb3d8bbwe
- RegistryPath : 
- RegistryName : 
- Value : aimgr_0.20.47.0_x64__8wekyb3d8bbwe
- RecommendedAction : Ne pas supprimer brutalement. Vérifier la fonctionnalité associée et préférer un contrôle par politique.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Composant système Microsoft, suppression déconseillée
- Method : Préférer politiques de désactivation, paramètres Windows ou image Windows personnalisée
- WhereToFind : C:\Program Files\WindowsApps\aimgr_0.20.47.0_x64__8wekyb3d8bbwe
- RelativePath : %ProgramFiles%\WindowsApps\aimgr_0.20.47.0_x64__8wekyb3d8bbwe
- RegistryName : 
- CurrentValue : aimgr_0.20.47.0_x64__8wekyb3d8bbwe
- DisableHint : Chercher une politique HKLM ou HKCU liée à WindowsAI, WindowsCopilot ou Recall
- RemoveHint : Suppression directe non recommandée
- Warning : Ne pas supprimer brutalement WindowsApps ou SystemApps. Risque de casser Windows ou de revenir après mise à jour.

### MicrosoftWindows.Client.CoreAI

- Category : confirmed_ai_component
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Paquet Appx Windows lié à l’écosystème IA Microsoft
- RelativePath : C:\Windows\SystemApps\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy
- RegistryPath : 
- RegistryName : 
- Value : MicrosoftWindows.Client.CoreAI_1000.26100.8328.0_x64__cw5n1h2txyewy
- RecommendedAction : Ne pas supprimer brutalement. Vérifier la fonctionnalité associée et préférer un contrôle par politique.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Composant système Microsoft, suppression déconseillée
- Method : Préférer politiques de désactivation, paramètres Windows ou image Windows personnalisée
- WhereToFind : C:\Windows\SystemApps\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy
- RelativePath : C:\Windows\SystemApps\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy
- RegistryName : 
- CurrentValue : MicrosoftWindows.Client.CoreAI_1000.26100.8328.0_x64__cw5n1h2txyewy
- DisableHint : Chercher une politique HKLM ou HKCU liée à WindowsAI, WindowsCopilot ou Recall
- RemoveHint : Suppression directe non recommandée
- Warning : Ne pas supprimer brutalement WindowsApps ou SystemApps. Risque de casser Windows ou de revenir après mise à jour.

### Microsoft.AIFabric.CBS.1.6

- Category : confirmed_ai_component
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Paquet Appx Windows lié à l’écosystème IA Microsoft
- RelativePath : C:\Windows\SystemApps\Microsoft.AIFabric.CBS.1.6_8wekyb3d8bbwe
- RegistryPath : 
- RegistryName : 
- Value : Microsoft.AIFabric.CBS.1.6_1.6.935.100_x64__8wekyb3d8bbwe
- RecommendedAction : Ne pas supprimer brutalement. Vérifier la fonctionnalité associée et préférer un contrôle par politique.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Composant système Microsoft, suppression déconseillée
- Method : Préférer politiques de désactivation, paramètres Windows ou image Windows personnalisée
- WhereToFind : C:\Windows\SystemApps\Microsoft.AIFabric.CBS.1.6_8wekyb3d8bbwe
- RelativePath : C:\Windows\SystemApps\Microsoft.AIFabric.CBS.1.6_8wekyb3d8bbwe
- RegistryName : 
- CurrentValue : Microsoft.AIFabric.CBS.1.6_1.6.935.100_x64__8wekyb3d8bbwe
- DisableHint : Chercher une politique HKLM ou HKCU liée à WindowsAI, WindowsCopilot ou Recall
- RemoveHint : Suppression directe non recommandée
- Warning : Ne pas supprimer brutalement WindowsApps ou SystemApps. Risque de casser Windows ou de revenir après mise à jour.

### ModelCachingIdle

- Category : windows_ai_feature
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Tâche planifiée WindowsAI détectée
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle
- RegistryPath : 
- RegistryName : 
- Value : Ready
- RecommendedAction : Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Désactivation possible à vérifier, suppression déconseillée
- Method : Vérifier dans le Planificateur de tâches et préférer les politiques Windows
- WhereToFind : taskschd.msc > Bibliothèque du Planificateur de tâches > \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle
- RegistryName : 
- CurrentValue : Ready
- DisableHint : Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation
- Warning : Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration.

### ModelCachingLimit

- Category : windows_ai_feature
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Tâche planifiée WindowsAI détectée
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit
- RegistryPath : 
- RegistryName : 
- Value : Ready
- RecommendedAction : Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Désactivation possible à vérifier, suppression déconseillée
- Method : Vérifier dans le Planificateur de tâches et préférer les politiques Windows
- WhereToFind : taskschd.msc > Bibliothèque du Planificateur de tâches > \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit
- RegistryName : 
- CurrentValue : Ready
- DisableHint : Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation
- Warning : Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration.

### ModelCachingUpdate

- Category : windows_ai_feature
- Severity : Medium
- RiskContribution : 4
- HardeningContribution : 0
- Confidence : High
- Description : Tâche planifiée WindowsAI détectée
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate
- RegistryPath : 
- RegistryName : 
- Value : Ready
- RecommendedAction : Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Désactivation possible à vérifier, suppression déconseillée
- Method : Vérifier dans le Planificateur de tâches et préférer les politiques Windows
- WhereToFind : taskschd.msc > Bibliothèque du Planificateur de tâches > \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate
- RelativePath : \Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate
- RegistryName : 
- CurrentValue : Ready
- DisableHint : Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation
- Warning : Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration.

### InitialConfiguration

- Category : windows_ai_feature
- Severity : High
- RiskContribution : 7
- HardeningContribution : 0
- Confidence : High
- Description : Tâche planifiée WindowsAI détectée
- RelativePath : \Microsoft\Windows\WindowsAI\Recall\InitialConfiguration
- RegistryPath : 
- RegistryName : 
- Value : Disabled
- RecommendedAction : Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Désactivation possible à vérifier, suppression déconseillée
- Method : Vérifier dans le Planificateur de tâches et préférer les politiques Windows
- WhereToFind : taskschd.msc > Bibliothèque du Planificateur de tâches > \Microsoft\Windows\WindowsAI\Recall\InitialConfiguration
- RelativePath : \Microsoft\Windows\WindowsAI\Recall\InitialConfiguration
- RegistryName : 
- CurrentValue : Disabled
- DisableHint : Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation
- Warning : Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration.

### PolicyConfiguration

- Category : windows_ai_feature
- Severity : High
- RiskContribution : 7
- HardeningContribution : 0
- Confidence : High
- Description : Tâche planifiée WindowsAI détectée
- RelativePath : \Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration
- RegistryPath : 
- RegistryName : 
- Value : Ready
- RecommendedAction : Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction.

#### Remediation
- CanDelete : False
- CanDisable : True
- Safety : Désactivation possible à vérifier, suppression déconseillée
- Method : Vérifier dans le Planificateur de tâches et préférer les politiques Windows
- WhereToFind : taskschd.msc > Bibliothèque du Planificateur de tâches > \Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration
- RelativePath : \Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration
- RegistryName : 
- CurrentValue : Ready
- DisableHint : Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation
- Warning : Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration.

### Ressources Microsoft AugLoop

- Category : office_ai_resource
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : High
- Description : Ressources Microsoft AugLoop
- RelativePath : %USERPROFILE%\AppData\Local\Microsoft\AugLoop
- RegistryPath : 
- RegistryName : 
- Value : 10.25 MB
- RecommendedAction : Vérifier le contenu du dossier. Supprimer uniquement si l’application associée est connue et si une sauvegarde ou validation existe.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression prudente uniquement si Office est fermé
- Method : Fermer Office puis vérifier le dossier Microsoft AugLoop
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Microsoft\AugLoop
- RelativePath : %USERPROFILE%\AppData\Local\Microsoft\AugLoop
- RegistryName : 
- CurrentValue : 10.25 MB
- DisableHint : Chercher les politiques Microsoft 365 ou Copilot adaptées à ton environnement
- RemoveHint : Fermer Word, Excel, Office et OneDrive puis supprimer le cache uniquement si validé
- Warning : Office peut recréer ce dossier après mise à jour ou synchronisation.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\13\C0DAB6922330736D\FEDA0F6370F75AB9\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 1.16 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\13\C0DAB6922330736D\FEDA0F6370F75AB9\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\13\C0DAB6922330736D\FEDA0F6370F75AB9\model.tflite
- RegistryName : 
- CurrentValue : 1.16 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\15\C0DAB6922330736D\FA585745F46E0FF3\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 2.61 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\15\C0DAB6922330736D\FA585745F46E0FF3\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\15\C0DAB6922330736D\FA585745F46E0FF3\model.tflite
- RegistryName : 
- CurrentValue : 2.61 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\2\C0DAB6922330736D\D805EDCEFD6F1E80\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.37 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\2\C0DAB6922330736D\D805EDCEFD6F1E80\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\2\C0DAB6922330736D\D805EDCEFD6F1E80\model.tflite
- RegistryName : 
- CurrentValue : 0.37 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\20\C0DAB6922330736D\C2AA443CA99A4762\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.03 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\20\C0DAB6922330736D\C2AA443CA99A4762\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\20\C0DAB6922330736D\C2AA443CA99A4762\model.tflite
- RegistryName : 
- CurrentValue : 0.03 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.17 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\model.tflite
- RegistryName : 
- CurrentValue : 0.17 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### visual_model_desktop.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\visual_model_desktop.tflite
- RegistryPath : 
- RegistryName : 
- Value : 3.29 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\visual_model_desktop.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\25\C0DAB6922330736D\16FF22152500173B\visual_model_desktop.tflite
- RegistryName : 
- CurrentValue : 3.29 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\26\C0DAB6922330736D\270F8F1689DD2E92\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.01 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\26\C0DAB6922330736D\270F8F1689DD2E92\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\26\C0DAB6922330736D\270F8F1689DD2E92\model.tflite
- RegistryName : 
- CurrentValue : 0.01 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\30\C0DAB6922330736D\5A710A776CDA22BE\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 6.44 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\30\C0DAB6922330736D\5A710A776CDA22BE\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\30\C0DAB6922330736D\5A710A776CDA22BE\model.tflite
- RegistryName : 
- CurrentValue : 6.44 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\40\C0DAB6922330736D\E492AC71496512D5\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\40\C0DAB6922330736D\E492AC71496512D5\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\40\C0DAB6922330736D\E492AC71496512D5\model.tflite
- RegistryName : 
- CurrentValue : 0 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\43\C0DAB6922330736D\F6E05FAA949BF2AF\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 35.07 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\43\C0DAB6922330736D\F6E05FAA949BF2AF\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\43\C0DAB6922330736D\F6E05FAA949BF2AF\model.tflite
- RegistryName : 
- CurrentValue : 35.07 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\45\C0DAB6922330736D\3FE321A6971A4668\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.13 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\45\C0DAB6922330736D\3FE321A6971A4668\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\45\C0DAB6922330736D\3FE321A6971A4668\model.tflite
- RegistryName : 
- CurrentValue : 0.13 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\49\C0DAB6922330736D\E5CF390DB6444951\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\49\C0DAB6922330736D\E5CF390DB6444951\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\49\C0DAB6922330736D\E5CF390DB6444951\model.tflite
- RegistryName : 
- CurrentValue : 0 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\51\C0DAB6922330736D\A7B87589CC8ECA57\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\51\C0DAB6922330736D\A7B87589CC8ECA57\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\51\C0DAB6922330736D\A7B87589CC8ECA57\model.tflite
- RegistryName : 
- CurrentValue : 0 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\55\C0DAB6922330736D\1D54F00E26BEBC71\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\55\C0DAB6922330736D\1D54F00E26BEBC71\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\55\C0DAB6922330736D\1D54F00E26BEBC71\model.tflite
- RegistryName : 
- CurrentValue : 0 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\59\C0DAB6922330736D\24358FAF64F19D63\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\59\C0DAB6922330736D\24358FAF64F19D63\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\59\C0DAB6922330736D\24358FAF64F19D63\model.tflite
- RegistryName : 
- CurrentValue : 0 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.tflite

- Category : browser_ai_cache
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\9\C0DAB6922330736D\099F5429AF432501\model.tflite
- RegistryPath : 
- RegistryName : 
- Value : 0.03 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression possible mais le navigateur peut retélécharger le cache
- Method : Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\9\C0DAB6922330736D\099F5429AF432501\model.tflite
- RelativePath : %USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store\9\C0DAB6922330736D\099F5429AF432501\model.tflite
- RegistryName : 
- CurrentValue : 0.03 MB
- DisableHint : Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions
- RemoveHint : Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage
- Warning : Le cache peut revenir après mise à jour ou relance du navigateur.

### model.onnx

- Category : office_ai_resource
- Severity : Medium
- RiskContribution : 2
- HardeningContribution : 0
- Confidence : Medium
- Description : Ressource Microsoft Office ou AugLoop pouvant être liée à des fonctionnalités assistées
- RelativePath : %USERPROFILE%\AppData\Local\Microsoft\AugLoop\Word\2.1\CloudResources\ModelResources\en-us\model.onnx
- RegistryPath : 
- RegistryName : 
- Value : 8.44 MB
- RecommendedAction : Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation.

#### Remediation
- CanDelete : True
- CanDisable : True
- Safety : Suppression prudente uniquement si Office est fermé
- Method : Fermer Office puis vérifier le dossier Microsoft AugLoop
- WhereToFind : C:\Users\Utilisateur\AppData\Local\Microsoft\AugLoop\Word\2.1\CloudResources\ModelResources\en-us\model.onnx
- RelativePath : %USERPROFILE%\AppData\Local\Microsoft\AugLoop\Word\2.1\CloudResources\ModelResources\en-us\model.onnx
- RegistryName : 
- CurrentValue : 8.44 MB
- DisableHint : Chercher les politiques Microsoft 365 ou Copilot adaptées à ton environnement
- RemoveHint : Fermer Word, Excel, Office et OneDrive puis supprimer le cache uniquement si validé
- Warning : Office peut recréer ce dossier après mise à jour ou synchronisation.

### GenAILocalFoundationalModelSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GenAILocalFoundationalModelSettings
- Value : 1
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GenAILocalFoundationalModelSettings
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### AIModeSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : AIModeSettings
- Value : 1
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : AIModeSettings
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### CreateThemesSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : CreateThemesSettings
- Value : 2
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : CreateThemesSettings
- CurrentValue : 2
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### DevToolsGenAiSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : DevToolsGenAiSettings
- Value : 2
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : DevToolsGenAiSettings
- CurrentValue : 2
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### GeminiActOnWebSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GeminiActOnWebSettings
- Value : 1
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GeminiActOnWebSettings
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### GeminiSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GeminiSettings
- Value : 1
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : GeminiSettings
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### HelpMeWriteSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : HelpMeWriteSettings
- Value : 2
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : HelpMeWriteSettings
- CurrentValue : 2
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### HistorySearchSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : HistorySearchSettings
- Value : 2
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : HistorySearchSettings
- CurrentValue : 2
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### SearchContentSharingSettings

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Chrome GenAI détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : SearchContentSharingSettings
- Value : 1
- RecommendedAction : Vérifier dans chrome://policy que la politique est bien appliquée et en état OK.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Google\Chrome
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Google\Chrome
- RegistryName : SearchContentSharingSettings
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### AIGenThemesEnabled

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Edge liée aux fonctions IA ou Copilot détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : AIGenThemesEnabled
- Value : 0
- RecommendedAction : Vérifier dans edge://policy que la politique est bien appliquée.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : AIGenThemesEnabled
- CurrentValue : 0
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### CopilotPageContext

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Edge liée aux fonctions IA ou Copilot détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : CopilotPageContext
- Value : 0
- RecommendedAction : Vérifier dans edge://policy que la politique est bien appliquée.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : CopilotPageContext
- CurrentValue : 0
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### HubsSidebarEnabled

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Edge liée aux fonctions IA ou Copilot détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : HubsSidebarEnabled
- Value : 0
- RecommendedAction : Vérifier dans edge://policy que la politique est bien appliquée.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : HubsSidebarEnabled
- CurrentValue : 0
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### ComposeInlineEnabled

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Politique Edge liée aux fonctions IA ou Copilot détectée
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : ComposeInlineEnabled
- Value : 0
- RecommendedAction : Vérifier dans edge://policy que la politique est bien appliquée.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Edge
- RegistryName : ComposeInlineEnabled
- CurrentValue : 0
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### TurnOffWindowsCopilot

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Désactivation de Windows Copilot au niveau machine
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RegistryName : TurnOffWindowsCopilot
- Value : 1
- RecommendedAction : Vérifier la politique. Une valeur 1 est généralement attendue pour une désactivation quand la politique le prévoit.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RegistryName : TurnOffWindowsCopilot
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### TurnOffWindowsCopilot

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Désactivation de Windows Copilot au niveau utilisateur
- RelativePath : 
- RegistryPath : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RegistryName : TurnOffWindowsCopilot
- Value : 1
- RecommendedAction : Vérifier la politique. Une valeur 1 est généralement attendue pour une désactivation quand la politique le prévoit.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RelativePath : 
- RegistryPath : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
- RegistryName : TurnOffWindowsCopilot
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### DisableAIDataAnalysis

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Désactivation de certaines analyses IA Windows
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RegistryName : DisableAIDataAnalysis
- Value : 1
- RecommendedAction : Vérifier la politique. Une valeur 1 est généralement attendue pour une désactivation quand la politique le prévoit.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RelativePath : 
- RegistryPath : HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RegistryName : DisableAIDataAnalysis
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

### DisableAIDataAnalysis

- Category : policy_hardening
- Severity : Low
- RiskContribution : 0
- HardeningContribution : 2
- Confidence : High
- Description : Désactivation de certaines analyses IA Windows côté utilisateur
- RelativePath : 
- RegistryPath : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RegistryName : DisableAIDataAnalysis
- Value : 1
- RecommendedAction : Vérifier la politique. Une valeur 1 est généralement attendue pour une désactivation quand la politique le prévoit.

#### Remediation
- CanDelete : False
- CanDisable : False
- Safety : Mesure de protection, à conserver si elle est voulue
- Method : Vérifier dans le registre et dans la page de politiques du navigateur
- WhereToFind : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RelativePath : 
- RegistryPath : HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
- RegistryName : DisableAIDataAnalysis
- CurrentValue : 1
- DisableHint : Ne pas supprimer cette politique si elle sert au durcissement
- RemoveHint : Suppression déconseillée car la politique semble protectrice
- Warning : Retirer cette politique peut réactiver des fonctionnalités IA.

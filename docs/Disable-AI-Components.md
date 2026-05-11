# AI Integrity Remediation

Script PowerShell de remédiation défensive pour désactiver ou neutraliser certains composants liés à l’IA dans un environnement Windows.

Ce projet a été conçu pour un usage local, défensif et pédagogique, principalement dans une machine virtuelle Windows fraîchement installée.

## Objectif

L’objectif du script est de réduire l’activité potentielle de composants IA intégrés ou associés à Windows, Chrome, Edge et Microsoft Office, sans supprimer brutalement les composants système.

Le script privilégie une approche prudente :

- désactivation des tâches planifiées liées à WindowsAI
- application ou renforcement de politiques Windows
- application ou renforcement de politiques Chrome et Edge
- nettoyage optionnel de caches IA locaux
- génération d’un rapport JSON de remédiation
- mode simulation par défaut

## Avertissement

Ce projet est destiné aux tests défensifs et au durcissement local dans un environnement Windows contrôlé, notamment en machine virtuelle.

Le script de remédiation est non destructif par défaut et doit être testé en mode simulation avant toute application réelle des changements.

Il est recommandé de créer un snapshot de la VM ou un point de restauration avant d’utiliser le mode `-Apply`.

## Fonctionnalités

Le script peut :

- désactiver les tâches WindowsAI liées à ClickToDo
- désactiver les tâches WindowsAI liées à Recall
- appliquer des politiques de désactivation de Windows Copilot
- appliquer des politiques de désactivation de certaines analyses IA Windows
- appliquer des politiques Chrome GenAI
- appliquer des politiques Edge liées à certaines fonctionnalités IA
- fermer Chrome, Edge et Office avant nettoyage
- nettoyer certains caches IA locaux
- générer un rapport JSON détaillé

## Ce que le script ne fait pas

Le script ne supprime pas les composants système sensibles suivants :

- `WindowsApps`
- `SystemApps`
- `aimgr`
- `MicrosoftWindows.Client.CoreAI`
- `Microsoft.AIFabric.CBS`

Le script ne supprime pas non plus les politiques Chrome protectrices.

L’objectif est de rendre les composants non actifs quand cela est possible, pas de casser Windows.

## Prérequis

- Windows 10 ou Windows 11
- PowerShell 7 recommandé
- Exécution dans une console PowerShell
- Droits administrateur recommandés
- Machine virtuelle ou environnement de test conseillé

## Fichier principal

```text
Disable-AI-Components.ps1
```

## Utilisation

### Mode simulation

Le mode simulation affiche ce que le script ferait sans appliquer de changement.

```powershell
.\Disable-AI-Components.ps1 -DisableWindowsAITasks -SetWindowsAIPolicies -SetBrowserAIPolicies -CleanAICaches
```

### Mode application réelle

Le mode application réelle applique les changements demandés.

```powershell
.\Disable-AI-Components.ps1 -Apply -DisableWindowsAITasks -SetWindowsAIPolicies -SetBrowserAIPolicies -CleanAICaches
```

## Options disponibles

### `-Apply`

Applique réellement les changements.

Sans cette option, le script reste en simulation.

### `-DisableWindowsAITasks`

Désactive les tâches planifiées liées à WindowsAI, ClickToDo et Recall.

Tâches ciblées :

```text
\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle
\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit
\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate
\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration
\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration
```

### `-SetWindowsAIPolicies`

Ajoute ou renforce des politiques Windows liées à Copilot et WindowsAI.

Clés ciblées :

```text
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
```

Valeurs configurées :

```text
TurnOffWindowsCopilot = 1
DisableAIDataAnalysis = 1
```

### `-SetBrowserAIPolicies`

Ajoute ou renforce des politiques Chrome et Edge liées aux fonctionnalités IA.

Clés Chrome ciblées :

```text
HKLM:\SOFTWARE\Policies\Google\Chrome
```

Politiques Chrome configurées :

```text
GenAILocalFoundationalModelSettings = 1
AIModeSettings = 1
CreateThemesSettings = 2
DevToolsGenAiSettings = 2
GeminiActOnWebSettings = 1
GeminiSettings = 1
HelpMeWriteSettings = 2
HistorySearchSettings = 2
SearchContentSharingSettings = 1
```

Clés Edge ciblées :

```text
HKLM:\SOFTWARE\Policies\Microsoft\Edge
```

Politiques Edge configurées :

```text
HubsSidebarEnabled = 0
CopilotPageContext = 0
DiscoverPageContextEnabled = 0
ComposeInlineEnabled = 0
```

### `-CleanAICaches`

Ferme les applications concernées puis nettoie certains caches IA locaux.

Caches ciblés :

```text
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\OnDeviceHeadSuggestModel
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\optimization_guide_model_store
%USERPROFILE%\AppData\Local\Microsoft\AugLoop
```

Applications fermées avant nettoyage :

```text
chrome
msedge
winword
excel
powerpnt
onenote
outlook
onedrive
```

## Rapport généré

Le script génère un rapport JSON dans le dossier suivant :

```text
.\result\
```

Exemple :

```text
.\result\ai_disable_report_2026-05-11_09-30-00.json
```

Le rapport contient :

- la date d’exécution
- le mode utilisé
- les options activées
- les actions réalisées ou simulées
- les erreurs éventuelles
- les chemins ciblés
- les valeurs registre appliquées ou prévues

## Exemple de workflow recommandé

### 1. Créer un snapshot de la VM

Avant toute modification réelle, créer un snapshot ou un point de restauration.

### 2. Lancer une simulation

```powershell
.\Disable-AI-Components.ps1 -DisableWindowsAITasks -SetWindowsAIPolicies -SetBrowserAIPolicies -CleanAICaches
```

### 3. Lire le rapport JSON

Vérifier le rapport généré dans :

```text
.\result\
```

### 4. Appliquer réellement

```powershell
.\Disable-AI-Components.ps1 -Apply -DisableWindowsAITasks -SetWindowsAIPolicies -SetBrowserAIPolicies -CleanAICaches
```

### 5. Redémarrer la VM

Un redémarrage est conseillé afin de vérifier que les tâches et politiques sont bien prises en compte.

### 6. Relancer l’audit

Relancer le script d’audit pour comparer l’état avant et après remédiation.

```powershell
.\Check-AI-Integrity-v2.3.ps1 -IncludeBrowserCache
```

## Vérifications manuelles

### Vérifier les tâches WindowsAI

```powershell
Get-ScheduledTask |
Where-Object { $_.TaskPath -like "\Microsoft\Windows\WindowsAI\*" } |
Select-Object TaskPath, TaskName, State
```

### Vérifier les politiques Chrome

```powershell
reg query "HKLM\SOFTWARE\Policies\Google\Chrome"
```

Dans Chrome :

```text
chrome://policy
```

Puis cliquer sur `Reload policies`.

### Vérifier les politiques Edge

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Edge"
```

Dans Edge :

```text
edge://policy
```

## Limites

Ce script ne garantit pas la suppression complète de toutes les fonctionnalités IA.

Certaines fonctionnalités peuvent être :

- intégrées à Windows
- réinstallées après mise à jour
- recréées par Chrome, Edge ou Office
- dépendantes de politiques non documentées
- dépendantes de services côté serveur

Le script vise surtout à réduire l’activité locale visible et à appliquer un durcissement raisonnable.

## Recommandations

- Tester d’abord en VM
- Utiliser le mode simulation
- Lire le rapport JSON avant application réelle
- Ne pas supprimer manuellement les dossiers système
- Préférer les politiques de désactivation
- Relancer l’audit après remédiation
- Comparer les rapports avant et après

## Licence

Ce projet est publié sous licence MIT.

## Auteur

Potate_Bulle / ShadowSc0pe

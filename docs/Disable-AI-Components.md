# AI Integrity Remediation

Script PowerShell de remédiation défensive permettant de désactiver ou de neutraliser certains composants liés à l’IA dans un environnement Windows.

Ce projet a été conçu pour un usage local, défensif et pédagogique, principalement dans une machine virtuelle Windows fraîchement installée.

## Objectif

L’objectif du script est de réduire l’activité potentielle de composants IA intégrés ou associés à Windows, Chrome et Microsoft Office, sans supprimer brutalement les composants système.

Le script privilégie une approche prudente :

- désactivation des tâches planifiées liées à WindowsAI
- nettoyage optionnel des caches IA locaux de Chrome
- nettoyage optionnel des ressources Microsoft AugLoop
- génération d’un rapport JSON de remédiation
- mode simulation par défaut

## Avertissement

Ce projet est destiné aux tests défensifs et au durcissement local dans un environnement Windows contrôlé, notamment en machine virtuelle.

Le script de remédiation est non destructif par défaut et doit être testé en mode simulation avant toute application réelle des changements.

Il est recommandé de créer un snapshot de la VM ou un point de restauration avant d’utiliser le mode `-Apply`.

## Fonctionnalités

Le script peut :

- désactiver les tâches WindowsAI liées à ClickToDo
- désactiver certaines tâches WindowsAI liées à Recall
- vérifier la présence de politiques Chrome protectrices
- fermer Chrome avant nettoyage
- nettoyer certains caches IA locaux de Chrome
- fermer les applications Office avant nettoyage
- nettoyer le dossier Microsoft AugLoop
- générer un rapport JSON détaillé

## Ce que le script ne fait pas

Le script ne supprime pas les composants système sensibles suivants :

- `WindowsApps`
- `SystemApps`
- `aimgr`
- `MicrosoftWindows.Client.CoreAI`
- `Microsoft.AIFabric.CBS`

Le script ne supprime pas non plus les politiques Chrome protectrices.

L’objectif est de rendre certains composants non actifs quand cela est possible, pas de casser Windows.

## Prérequis

- Windows 10 ou Windows 11
- PowerShell 7 recommandé
- Exécution dans une console PowerShell
- Droits administrateurice recommandés
- Machine virtuelle ou environnement de test conseillé

## Fichier principal

```text
Disable-AI-Components.ps1
```

## Paramètres disponibles

Le script actuel accepte les paramètres suivants :

```text
-Apply
-DisableWindowsAITasks
-CleanChromeAICache
-CleanOfficeAugLoop
-OutputDirectory
```

Pour vérifier les paramètres disponibles directement depuis PowerShell :

```powershell
(Get-Command .\Disable-AI-Components.ps1).Parameters.Keys
```

## Utilisation

### Mode simulation

Le mode simulation affiche ce que le script ferait sans appliquer de changement.

```powershell
.\Disable-AI-Components.ps1 -DisableWindowsAITasks -CleanChromeAICache -CleanOfficeAugLoop
```

### Mode application réelle

Le mode application réelle applique les changements demandés.

```powershell
.\Disable-AI-Components.ps1 -Apply -DisableWindowsAITasks -CleanChromeAICache -CleanOfficeAugLoop
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

### `-CleanChromeAICache`

Ferme Chrome puis nettoie certains caches locaux liés à des ressources IA ou à des modèles de suggestion.

Caches ciblés :

```text
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\OnDeviceHeadSuggestModel
```

Application fermée avant nettoyage :

```text
chrome
```

### `-CleanOfficeAugLoop`

Ferme les applications Office puis nettoie le dossier Microsoft AugLoop.

Cache ciblé :

```text
%USERPROFILE%\AppData\Local\Microsoft\AugLoop
```

Applications fermées avant nettoyage :

```text
winword
excel
powerpnt
onenote
outlook
onedrive
```

### `-OutputDirectory`

Permet de choisir le dossier de sortie du rapport JSON.

Exemple :

```powershell
.\Disable-AI-Components.ps1 -OutputDirectory ".\result"
```

## Rapport généré

Le script génère un rapport JSON dans le dossier suivant :

```text
.\result\
```

Exemple :

```text
.\result\ai_remediation_report_2026-05-11_09-30-00.json
```

Le rapport contient :

- la date d’exécution
- le mode utilisé
- les options activées
- les actions réalisées ou simulées
- les erreurs éventuelles
- les chemins ciblés
- l’état des tâches ou chemins vérifiés

## Exemple de workflow recommandé

### 1. Créer un snapshot de la VM

Avant toute modification réelle, créer un snapshot ou un point de restauration.

### 2. Lancer une simulation

```powershell
.\Disable-AI-Components.ps1 -DisableWindowsAITasks -CleanChromeAICache -CleanOfficeAugLoop
```

### 3. Lire le rapport JSON

Vérifier le rapport généré dans :

```text
.\result\
```

### 4. Appliquer réellement

```powershell
.\Disable-AI-Components.ps1 -Apply -DisableWindowsAITasks -CleanChromeAICache -CleanOfficeAugLoop
```

### 5. Redémarrer la VM

Un redémarrage est conseillé afin de vérifier que les tâches sont bien désactivées et que les caches ne sont plus actifs.

### 6. Relancer l’audit

Relancer le script d’audit pour comparer l’état avant et après remédiation.

```powershell
.\Check-AI-Integrity.ps1 -IncludeBrowserCache
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

## Limites

Ce script ne garantit pas la suppression complète de toutes les fonctionnalités IA.

Certaines fonctionnalités peuvent être :

- intégrées à Windows
- réinstallées après mise à jour
- recréées par Chrome ou Office
- dépendantes de politiques non documentées
- dépendantes de services côté serveur

Le script vise surtout à réduire l’activité locale visible et à appliquer une remédiation raisonnable.

## Recommandations

- Tester d’abord en VM
- Utiliser le mode simulation
- Lire le rapport JSON avant application réelle
- Ne pas supprimer manuellement les dossiers système
- Préférer la désactivation plutôt que la suppression brute
- Relancer l’audit après remédiation
- Comparer les rapports avant et après

## Licence

Ce projet est publié sous licence MIT.

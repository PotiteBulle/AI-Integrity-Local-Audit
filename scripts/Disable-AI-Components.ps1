<#
.SYNOPSIS
    Remediation prudente des composants IA détectés par Check-AI-Integrity.

.DESCRIPTION
    Script PowerShell défensif pour Windows.
    Par défaut, le script fonctionne en mode simulation.
    Il ne modifie rien tant que le paramètre -Apply n’est pas utilisé.

    Actions prévues :
    - Vérifier les politiques Chrome protectrices
    - Désactiver certaines tâches WindowsAI et Recall si demandé
    - Nettoyer les caches Chrome liés à optimization_guide_model_store
    - Nettoyer OnDeviceHeadSuggestModel
    - Nettoyer Microsoft AugLoop
    - Générer un rapport JSON de remédiation

    Le script ne supprime pas les composants système WindowsApps ou SystemApps.
    Le script ne supprime pas aimgr, CoreAI ou AIFabric.
    Le script ne supprime pas les politiques Chrome protectrices.

.PARAMETER Apply
    Applique réellement les actions.
    Sans ce paramètre, le script reste en simulation.

.PARAMETER DisableWindowsAITasks
    Désactive les tâches WindowsAI ClickToDo et Recall PolicyConfiguration.

.PARAMETER CleanChromeAICache
    Nettoie les caches Chrome liés aux modèles locaux et suggestions.

.PARAMETER CleanOfficeAugLoop
    Nettoie le cache Microsoft AugLoop après fermeture des applications Office.

.PARAMETER OutputDirectory
    Dossier de sortie du rapport JSON.

.EXAMPLE
    .\Remediate-AI-Components.ps1

.EXAMPLE
    .\Remediate-AI-Components.ps1 -Apply -DisableWindowsAITasks -CleanChromeAICache -CleanOfficeAugLoop

.NOTES
    Auteur : Potate_Bulle
    Usage : Remédiation défensive locale Windows
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$DisableWindowsAITasks,
    [switch]$CleanChromeAICache,
    [switch]$CleanOfficeAugLoop,
    [string]$OutputDirectory = ".\result"
)

$ErrorActionPreference = "SilentlyContinue"

$StartedAt = Get-Date
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

if (!(Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

$ReportPath = Join-Path -Path $OutputDirectory -ChildPath "ai_remediation_report_$Timestamp.json"

$Actions = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

function Add-ActionLog {
    param(
        [string]$Category,
        [string]$Action,
        [string]$Target,
        [string]$Mode,
        [string]$Status,
        [string]$Message
    )

    $Item = [ordered]@{
        Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Category = $Category
        Action = $Action
        Target = $Target
        Mode = $Mode
        Status = $Status
        Message = $Message
    }

    $Actions.Add($Item) | Out-Null
}

function Add-ErrorLog {
    param(
        [string]$Stage,
        [string]$Target,
        [string]$Message
    )

    $Item = [ordered]@{
        Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Stage = $Stage
        Target = $Target
        Message = $Message
    }

    $Errors.Add($Item) | Out-Null
}

function Invoke-SafeDisableTask {
    param(
        [string]$TaskPath,
        [string]$TaskName
    )

    $Target = "$TaskPath$TaskName"
    $Task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue

    if ($null -eq $Task) {
        Add-ActionLog -Category "windows_ai_task" -Action "DisableScheduledTask" -Target $Target -Mode "Check" -Status "NotFound" -Message "Tâche non trouvée"
        return
    }

    if ($Task.State -eq "Disabled") {
        Add-ActionLog -Category "windows_ai_task" -Action "DisableScheduledTask" -Target $Target -Mode "Check" -Status "AlreadyDisabled" -Message "Tâche déjà désactivée"
        return
    }

    if ($Apply) {
        try {
            Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Out-Null
            Add-ActionLog -Category "windows_ai_task" -Action "DisableScheduledTask" -Target $Target -Mode "Apply" -Status "Done" -Message "Tâche désactivée"
        }
        catch {
            Add-ErrorLog -Stage "DisableScheduledTask" -Target $Target -Message "Impossible de désactiver la tâche"
        }
    }
    else {
        Add-ActionLog -Category "windows_ai_task" -Action "DisableScheduledTask" -Target $Target -Mode "DryRun" -Status "WouldDisable" -Message "La tâche serait désactivée avec -Apply"
    }
}

function Invoke-SafeRemovePath {
    param(
        [string]$Path,
        [string]$Category,
        [string]$Reason
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    if (!(Test-Path -Path $Path)) {
        Add-ActionLog -Category $Category -Action "RemovePath" -Target $Path -Mode "Check" -Status "NotFound" -Message "Chemin absent"
        return
    }

    if ($Path -match "\\WindowsApps\\|\\SystemApps\\") {
        Add-ActionLog -Category $Category -Action "RemovePath" -Target $Path -Mode "Blocked" -Status "Blocked" -Message "Suppression bloquée car le chemin est sensible"
        return
    }

    if ($Apply) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Add-ActionLog -Category $Category -Action "RemovePath" -Target $Path -Mode "Apply" -Status "Done" -Message $Reason
        }
        catch {
            Add-ErrorLog -Stage "RemovePath" -Target $Path -Message "Suppression impossible"
        }
    }
    else {
        Add-ActionLog -Category $Category -Action "RemovePath" -Target $Path -Mode "DryRun" -Status "WouldRemove" -Message $Reason
    }
}

function Invoke-SafeStopProcess {
    param(
        [string[]]$Names,
        [string]$Reason
    )

    foreach ($Name in $Names) {
        $Processes = Get-Process -Name $Name -ErrorAction SilentlyContinue

        if ($null -eq $Processes) {
            Add-ActionLog -Category "process" -Action "StopProcess" -Target $Name -Mode "Check" -Status "NotRunning" -Message "Processus absent"
            continue
        }

        if ($Apply) {
            try {
                $Processes | Stop-Process -Force -ErrorAction Stop
                Add-ActionLog -Category "process" -Action "StopProcess" -Target $Name -Mode "Apply" -Status "Done" -Message $Reason
            }
            catch {
                Add-ErrorLog -Stage "StopProcess" -Target $Name -Message "Impossible de fermer le processus"
            }
        }
        else {
            Add-ActionLog -Category "process" -Action "StopProcess" -Target $Name -Mode "DryRun" -Status "WouldStop" -Message $Reason
        }
    }
}

function Test-ProtectiveChromePolicies {
    $PolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"

    $Policies = @(
        "GenAILocalFoundationalModelSettings",
        "AIModeSettings",
        "CreateThemesSettings",
        "DevToolsGenAiSettings",
        "GeminiActOnWebSettings",
        "GeminiSettings",
        "HelpMeWriteSettings",
        "HistorySearchSettings",
        "SearchContentSharingSettings"
    )

    foreach ($Policy in $Policies) {
        $Value = $null

        try {
            $Value = Get-ItemPropertyValue -Path $PolicyPath -Name $Policy -ErrorAction SilentlyContinue
        }
        catch {
            $Value = $null
        }

        if ($null -ne $Value) {
            Add-ActionLog -Category "policy_hardening" -Action "VerifyPolicy" -Target "$PolicyPath\$Policy" -Mode "Check" -Status "Present" -Message "Politique protectrice présente avec valeur $Value"
        }
        else {
            Add-ActionLog -Category "policy_hardening" -Action "VerifyPolicy" -Target "$PolicyPath\$Policy" -Mode "Check" -Status "Missing" -Message "Politique absente"
        }
    }
}

Write-Host ""
Write-Host "Remediation IA Windows"
Write-Host ""

if ($Apply) {
    Write-Host "Mode : APPLY"
    Write-Host "Les actions demandées seront appliquées"
}
else {
    Write-Host "Mode : DRY RUN"
    Write-Host "Aucune modification ne sera effectuée"
}

Write-Host ""

Add-ActionLog -Category "runtime" -Action "Start" -Target $env:COMPUTERNAME -Mode $(if ($Apply) { "Apply" } else { "DryRun" }) -Status "Started" -Message "Démarrage du script de remédiation"

Test-ProtectiveChromePolicies

if ($DisableWindowsAITasks) {
    Invoke-SafeDisableTask -TaskPath "\Microsoft\Windows\WindowsAI\ClickToDo\" -TaskName "ModelCachingIdle"
    Invoke-SafeDisableTask -TaskPath "\Microsoft\Windows\WindowsAI\ClickToDo\" -TaskName "ModelCachingLimit"
    Invoke-SafeDisableTask -TaskPath "\Microsoft\Windows\WindowsAI\ClickToDo\" -TaskName "ModelCachingUpdate"
    Invoke-SafeDisableTask -TaskPath "\Microsoft\Windows\WindowsAI\Recall\" -TaskName "PolicyConfiguration"
}
else {
    Add-ActionLog -Category "windows_ai_task" -Action "DisableScheduledTask" -Target "WindowsAI tasks" -Mode "Skipped" -Status "Skipped" -Message "Option -DisableWindowsAITasks non utilisée"
}

if ($CleanChromeAICache) {
    Invoke-SafeStopProcess -Names @("chrome") -Reason "Fermeture de Chrome avant nettoyage des caches IA"

    $ChromeOptimizationGuide = Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Local\Google\Chrome\User Data\optimization_guide_model_store"
    $ChromeHeadSuggest = Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Local\Google\Chrome\User Data\OnDeviceHeadSuggestModel"

    Invoke-SafeRemovePath -Path $ChromeOptimizationGuide -Category "browser_ai_cache" -Reason "Nettoyage du cache Chrome optimization_guide_model_store"
    Invoke-SafeRemovePath -Path $ChromeHeadSuggest -Category "browser_ai_cache" -Reason "Nettoyage du cache Chrome OnDeviceHeadSuggestModel"
}
else {
    Add-ActionLog -Category "browser_ai_cache" -Action "RemovePath" -Target "Chrome AI caches" -Mode "Skipped" -Status "Skipped" -Message "Option -CleanChromeAICache non utilisée"
}

if ($CleanOfficeAugLoop) {
    Invoke-SafeStopProcess -Names @("winword", "excel", "powerpnt", "onenote", "outlook", "onedrive") -Reason "Fermeture des applications Office avant nettoyage AugLoop"

    $AugLoopPath = Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Local\Microsoft\AugLoop"

    Invoke-SafeRemovePath -Path $AugLoopPath -Category "office_ai_resource" -Reason "Nettoyage du cache Microsoft AugLoop"
}
else {
    Add-ActionLog -Category "office_ai_resource" -Action "RemovePath" -Target "Microsoft AugLoop" -Mode "Skipped" -Status "Skipped" -Message "Option -CleanOfficeAugLoop non utilisée"
}

$EndedAt = Get-Date

$Report = [ordered]@{
    Metadata = [ordered]@{
        ReportName = "AI Remediation Report"
        GeneratedAt = $EndedAt.ToString("yyyy-MM-dd HH:mm:ss")
        Version = "V2.3"
        ApplyMode = [bool]$Apply
        NonDestructiveByDefault = $true
        OutputPath = $ReportPath
    }
    SystemInfo = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        StartedAt = $StartedAt.ToString("yyyy-MM-dd HH:mm:ss")
        EndedAt = $EndedAt.ToString("yyyy-MM-dd HH:mm:ss")
    }
    Options = [ordered]@{
        DisableWindowsAITasks = [bool]$DisableWindowsAITasks
        CleanChromeAICache = [bool]$CleanChromeAICache
        CleanOfficeAugLoop = [bool]$CleanOfficeAugLoop
    }
    Summary = [ordered]@{
        TotalActions = $Actions.Count
        Errors = $Errors.Count
        Mode = if ($Apply) { "Apply" } else { "DryRun" }
    }
    Actions = $Actions
    Errors = $Errors
}

$Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host ""
Write-Host "Rapport de remédiation : $ReportPath"
Write-Host "Actions journalisées : $($Actions.Count)"
Write-Host "Erreurs : $($Errors.Count)"
Write-Host ""

if (-not $Apply) {
    Write-Host "Simulation terminée"
    Write-Host "Relance avec -Apply pour appliquer réellement les actions sélectionnées"
}
else {
    Write-Host "Remédiation appliquée"
    Write-Host "Relance ensuite Check-AI-Integrity-v2.3.ps1 pour comparer"
}

Write-Host ""

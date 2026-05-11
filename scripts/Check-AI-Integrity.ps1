<#
.SYNOPSIS
    Audit v2.3 des composants IA présents sur une machine Windows.

.DESCRIPTION
    Script PowerShell défensif et non destructif.
    Il énumère les composants IA ou proches IA présents sur Windows.
    Il réduit les faux positifs par classification stricte.
    Il génère un rapport JSON et un rapport Markdown dans un dossier result.

    Cette version ajoute un bloc Remediation pour chaque finding.
    Le bloc Remediation explique où trouver le composant et comment le désactiver
    ou le supprimer quand cela est raisonnable.

    Le script ne supprime rien.
    Le script ne désactive rien.
    Le script ne modifie pas le registre.

.OUTPUT
    result\ai_integrity_report_v2_3_DATE.json
    result\ai_integrity_report_v2_3_DATE.md

.NOTES
    Auteur : Potate_Bulle
    Usage : Audit défensif local Windows
#>

[CmdletBinding()]
param(
    [switch]$DeepScan,
    [switch]$IncludeBrowserCache,
    [switch]$IncludeNvidiaDetails,
    [string]$OutputDirectory = ".\result"
)

$ErrorActionPreference = "SilentlyContinue"

$ScanStartedAt = Get-Date
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

if (!(Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}

$JsonReportPath = Join-Path -Path $OutputDirectory -ChildPath "ai_integrity_report_v2_3_$Timestamp.json"
$MarkdownReportPath = Join-Path -Path $OutputDirectory -ChildPath "ai_integrity_report_v2_3_$Timestamp.md"

$Findings = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

$KnownLocalAiApps = @(
    "Ollama",
    "LM Studio",
    "ComfyUI",
    "Stability Matrix",
    "Stable Diffusion",
    "AUTOMATIC1111",
    "InvokeAI",
    "GPT4All",
    "Jan",
    "AnythingLLM",
    "Open WebUI",
    "ChatGPT",
    "Claude",
    "Mistral",
    "LMStudio",
    "LocalAI",
    "KoboldCPP",
    "Fooocus",
    "A1111"
)

$WindowsAiAppxPatterns = @(
    "MicrosoftWindows.Client.CoreAI",
    "Microsoft.AIFabric",
    "aimgr",
    "WindowsAI",
    "Recall",
    "Copilot"
)

$BrowserAiPaths = @(
    "optimization_guide_model_store",
    "OnDeviceHeadSuggestModel",
    "MEIPreload",
    "segmentation_platform"
)

$OfficeAiPaths = @(
    "AugLoop",
    "ModelResources",
    "CloudResources",
    "Microsoft 365 Copilot",
    "Copilot"
)

$HighValueModelExtensions = @(
    ".gguf",
    ".ggml",
    ".safetensors",
    ".onnx",
    ".pt",
    ".pth",
    ".ckpt",
    ".tflite"
)

$WeakModelExtensions = @(
    ".bin"
)

$FalsePositivePathFragments = @(
    "\node_modules\.bin",
    "\Discord\app-",
    "\GitHubDesktop\app-",
    "\vscode",
    "\Code\User",
    "\npm-cache",
    "\Microsoft\Windows\INetCache",
    "\Temp",
    "\Cache\Cache_Data"
)

$FalsePositiveFileNames = @(
    "snapshot_blob.bin",
    "v8_context_snapshot.bin",
    "Nigori.bin",
    "icudtl.dat",
    "resources.pak"
)

$ChromeGenAiPolicies = @(
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

$EdgeAiPolicies = @(
    "AIGenThemesEnabled",
    "CopilotPageContext",
    "HubsSidebarEnabled",
    "EdgeShoppingAssistantEnabled",
    "ComposeInlineEnabled",
    "DiscoverPageContextEnabled"
)

$WindowsAiPolicyChecks = @(
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        Name = "TurnOffWindowsCopilot"
        ExpectedSecureValue = 1
        Description = "Désactivation de Windows Copilot au niveau machine"
    },
    @{
        Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        Name = "TurnOffWindowsCopilot"
        ExpectedSecureValue = 1
        Description = "Désactivation de Windows Copilot au niveau utilisateur"
    },
    @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        Name = "DisableAIDataAnalysis"
        ExpectedSecureValue = 1
        Description = "Désactivation de certaines analyses IA Windows"
    },
    @{
        Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        Name = "DisableAIDataAnalysis"
        ExpectedSecureValue = 1
        Description = "Désactivation de certaines analyses IA Windows côté utilisateur"
    }
)

$KnownAiFolders = @(
    @{
        Path = "$env:USERPROFILE\.ollama"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Dossier local Ollama"
    },
    @{
        Path = "$env:USERPROFILE\.cache\huggingface"
        Category = "local_model_cache"
        Severity = "Medium"
        Description = "Cache HuggingFace utilisateur"
    },
    @{
        Path = "$env:USERPROFILE\.cache\torch"
        Category = "local_model_cache"
        Severity = "Medium"
        Description = "Cache Torch utilisateur"
    },
    @{
        Path = "$env:USERPROFILE\.cache\transformers"
        Category = "local_model_cache"
        Severity = "Medium"
        Description = "Cache Transformers utilisateur"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\Programs\Ollama"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Installation utilisateur Ollama"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\LM Studio"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Installation utilisateur LM Studio"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Roaming\ComfyUI"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Configuration ComfyUI"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Roaming\StabilityMatrix"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Configuration Stability Matrix"
    },
    @{
        Path = "C:\Program Files\Ollama"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Installation machine Ollama"
    },
    @{
        Path = "C:\Program Files\LM Studio"
        Category = "local_ai_tool"
        Severity = "High"
        Description = "Installation machine LM Studio"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\optimization_guide_model_store"
        Category = "browser_ai_cache"
        Severity = "Medium"
        Description = "Ressources locales Chrome Optimization Guide"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\OnDeviceHeadSuggestModel"
        Category = "browser_ai_cache"
        Severity = "Low"
        Description = "Modèle local Chrome pour suggestions"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\optimization_guide_model_store"
        Category = "browser_ai_cache"
        Severity = "Medium"
        Description = "Ressources locales Edge Optimization Guide"
    },
    @{
        Path = "$env:USERPROFILE\AppData\Local\Microsoft\AugLoop"
        Category = "office_ai_resource"
        Severity = "Medium"
        Description = "Ressources Microsoft AugLoop"
    }
)

function Add-AuditError {
    param(
        [string]$Stage,
        [string]$Message
    )

    $Item = [ordered]@{
        Stage = $Stage
        Message = $Message
        Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    $Errors.Add($Item) | Out-Null
}

function Get-SeverityScore {
    param(
        [string]$Severity
    )

    switch ($Severity) {
        "Critical" { return 10 }
        "High" { return 7 }
        "Medium" { return 4 }
        "Low" { return 1 }
        default { return 0 }
    }
}

function Get-RiskContribution {
    param(
        [string]$Category,
        [string]$Severity
    )

    if ($Category -eq "policy_hardening") {
        return 0
    }

    if ($Category -eq "nvidia_component") {
        return 1
    }

    if ($Category -eq "browser_ai_cache") {
        return 2
    }

    if ($Category -eq "office_ai_resource") {
        return 2
    }

    return Get-SeverityScore -Severity $Severity
}

function Get-HardeningContribution {
    param(
        [string]$Category
    )

    if ($Category -eq "policy_hardening") {
        return 2
    }

    return 0
}

function Get-RelativePathSafe {
    param(
        [string]$InputPath
    )

    try {
        if ([string]::IsNullOrWhiteSpace($InputPath)) {
            return $null
        }

        $Relative = $InputPath

        if ($env:USERPROFILE) {
            $Relative = $Relative.Replace($env:USERPROFILE, "%USERPROFILE%")
        }

        if ($env:SystemRoot) {
            $Relative = $Relative.Replace($env:SystemRoot, "%SystemRoot%")
        }

        if ($env:ProgramFiles) {
            $Relative = $Relative.Replace($env:ProgramFiles, "%ProgramFiles%")
        }

        $ProgramFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")

        if ($ProgramFilesX86) {
            $Relative = $Relative.Replace($ProgramFilesX86, "%ProgramFiles(x86)%")
        }

        return $Relative
    }
    catch {
        return $InputPath
    }
}

function Get-FolderSizeBytes {
    param(
        [string]$InputPath
    )

    try {
        if (!(Test-Path -Path $InputPath)) {
            return 0
        }

        $Size = Get-ChildItem -Path $InputPath -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum

        if ($null -eq $Size.Sum) {
            return 0
        }

        return [int64]$Size.Sum
    }
    catch {
        Add-AuditError -Stage "FolderSize" -Message "Impossible de calculer la taille de $InputPath"
        return 0
    }
}

function Convert-BytesToMB {
    param(
        [int64]$Bytes
    )

    if ($Bytes -le 0) {
        return 0
    }

    return [math]::Round($Bytes / 1MB, 2)
}

function Test-AnyKeyword {
    param(
        [string]$Text,
        [string[]]$Keywords
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    foreach ($Keyword in $Keywords) {
        if ($Text -match [regex]::Escape($Keyword)) {
            return $true
        }
    }

    return $false
}

function Test-FalsePositivePath {
    param(
        [string]$InputPath,
        [string]$FileName
    )

    foreach ($Fragment in $FalsePositivePathFragments) {
        if ($InputPath -like "*$Fragment*") {
            return $true
        }
    }

    foreach ($Name in $FalsePositiveFileNames) {
        if ($FileName -ieq $Name) {
            return $true
        }
    }

    return $false
}

function Test-AppNameMatch {
    param(
        [string]$Text,
        [string[]]$Patterns
    )

    foreach ($Pattern in $Patterns) {
        if ($Text -match [regex]::Escape($Pattern)) {
            return $Pattern
        }
    }

    return $null
}

function Get-RegistryValueSafe {
    param(
        [string]$RegistryPath,
        [string]$Name
    )

    try {
        if (!(Test-Path -Path $RegistryPath)) {
            return $null
        }

        return Get-ItemPropertyValue -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue
    }
    catch {
        return $null
    }
}

function Get-RemediationGuidance {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path,
        [string]$RelativePath,
        [string]$RegistryPath,
        [string]$RegistryName,
        [object]$Value
    )

    $CanDelete = $false
    $CanDisable = $false
    $Safety = "Analyse manuelle recommandée"
    $Method = "Vérification manuelle"
    $WhereToFind = $null
    $DisableHint = $null
    $RemoveHint = $null
    $RegistryHint = $null
    $Warning = "Ne rien supprimer sans point de restauration ou sauvegarde."

    if ($Path) {
        $WhereToFind = $Path
    }

    if ($RegistryPath) {
        $RegistryHint = $RegistryPath
    }

    if ($Category -eq "local_ai_tool") {
        $CanDelete = $true
        $CanDisable = $true
        $Safety = "Suppression généralement possible si l’application n’est pas voulue"
        $Method = "Désinstallation propre via Applications installées ou winget si disponible"
        $RemoveHint = "Rechercher l’application dans Paramètres > Applications > Applications installées puis désinstaller proprement"
        $DisableHint = "Fermer l’application et retirer son lancement automatique si présent"
        $Warning = "Ne pas supprimer le dossier à la main avant la désinstallation propre."
    }

    if ($Category -eq "local_model_cache") {
        $CanDelete = $true
        $CanDisable = $false
        $Safety = "Suppression possible si aucun projet IA local ne l’utilise"
        $Method = "Suppression du cache après fermeture des outils Python ou IA"
        $RemoveHint = "Fermer les outils IA puis supprimer le dossier de cache indiqué"
        $Warning = "La suppression peut forcer un futur retéléchargement des modèles."
    }

    if ($Category -eq "local_model_candidate") {
        $CanDelete = $true
        $CanDisable = $false
        $Safety = "Suppression possible uniquement après identification du fichier"
        $Method = "Suppression manuelle du fichier après validation"
        $RemoveHint = "Identifier l’application propriétaire puis supprimer uniquement si le fichier est non désiré"
        $Warning = "Un fichier .onnx, .tflite, .pt ou .safetensors peut être nécessaire à une application légitime."
    }

    if ($Category -eq "browser_ai_cache") {
        $CanDelete = $true
        $CanDisable = $true
        $Safety = "Suppression possible mais le navigateur peut retélécharger le cache"
        $Method = "Fermer le navigateur puis supprimer le cache ciblé ou appliquer une politique de blocage"
        $RemoveHint = "Fermer Chrome ou Edge puis supprimer le dossier ou fichier indiqué si tu veux forcer un nettoyage"
        $DisableHint = "Préférer une politique navigateur dans HKLM ou HKCU pour empêcher le retour de certaines fonctions"
        $Warning = "Le cache peut revenir après mise à jour ou relance du navigateur."
    }

    if ($Category -eq "office_ai_resource") {
        $CanDelete = $true
        $CanDisable = $true
        $Safety = "Suppression prudente uniquement si Office est fermé"
        $Method = "Fermer Office puis vérifier le dossier Microsoft AugLoop"
        $RemoveHint = "Fermer Word, Excel, Office et OneDrive puis supprimer le cache uniquement si validé"
        $DisableHint = "Chercher les politiques Microsoft 365 ou Copilot adaptées à ton environnement"
        $Warning = "Office peut recréer ce dossier après mise à jour ou synchronisation."
    }

    if ($Category -eq "windows_ai_feature") {
        $CanDelete = $false
        $CanDisable = $true
        $Safety = "Désactivation possible à vérifier, suppression déconseillée"
        $Method = "Vérifier dans le Planificateur de tâches et préférer les politiques Windows"
        $WhereToFind = "taskschd.msc > Bibliothèque du Planificateur de tâches > " + $Path
        $DisableHint = "Dans taskschd.msc, vérifier la tâche puis désactiver uniquement après validation"
        $Warning = "Ne pas supprimer brutalement une tâche WindowsAI sans snapshot VM ou point de restauration."
    }

    if ($Category -eq "confirmed_ai_component") {
        $CanDelete = $false
        $CanDisable = $true
        $Safety = "Composant système Microsoft, suppression déconseillée"
        $Method = "Préférer politiques de désactivation, paramètres Windows ou image Windows personnalisée"
        $DisableHint = "Chercher une politique HKLM ou HKCU liée à WindowsAI, WindowsCopilot ou Recall"
        $RemoveHint = "Suppression directe non recommandée"
        $Warning = "Ne pas supprimer brutalement WindowsApps ou SystemApps. Risque de casser Windows ou de revenir après mise à jour."
    }

    if ($Category -eq "nvidia_component") {
        $CanDelete = $false
        $CanDisable = $false
        $Safety = "Composant fournisseur NVIDIA généralement légitime"
        $Method = "Gérer via NVIDIA App, pilote NVIDIA ou Applications installées"
        $RemoveHint = "Désinstaller uniquement le paquet NVIDIA concerné si tu sais exactement ce que tu retires"
        $Warning = "Peut affecter le pilote graphique ou les fonctionnalités NVIDIA."
    }

    if ($Category -eq "policy_hardening") {
        $CanDelete = $false
        $CanDisable = $false
        $Safety = "Mesure de protection, à conserver si elle est voulue"
        $Method = "Vérifier dans le registre et dans la page de politiques du navigateur"
        $WhereToFind = $RegistryPath
        $RegistryHint = $RegistryPath
        $DisableHint = "Ne pas supprimer cette politique si elle sert au durcissement"
        $RemoveHint = "Suppression déconseillée car la politique semble protectrice"
        $Warning = "Retirer cette politique peut réactiver des fonctionnalités IA."
    }

    if ($Category -eq "policy_gap") {
        $CanDelete = $false
        $CanDisable = $true
        $Safety = "Politique présente mais valeur à vérifier"
        $Method = "Corriger la valeur registre si la politique doit être durcie"
        $WhereToFind = $RegistryPath
        $RegistryHint = $RegistryPath
        $DisableHint = "Vérifier la valeur attendue puis corriger si nécessaire"
        $Warning = "Changer une politique registre doit être documenté."
    }

    if ($Category -eq "policy_missing") {
        $CanDelete = $false
        $CanDisable = $true
        $Safety = "Politique absente, durcissement possible"
        $Method = "Créer la politique registre si elle correspond à ton objectif"
        $WhereToFind = $RegistryPath
        $RegistryHint = $RegistryPath
        $DisableHint = "Créer la valeur de politique attendue si tu veux renforcer le poste"
        $Warning = "Créer une politique peut modifier le comportement Windows ou navigateur."
    }

    return [ordered]@{
        CanDelete = $CanDelete
        CanDisable = $CanDisable
        Safety = $Safety
        Method = $Method
        WhereToFind = $WhereToFind
        RelativePath = $RelativePath
        RegistryPath = $RegistryHint
        RegistryName = $RegistryName
        CurrentValue = $Value
        DisableHint = $DisableHint
        RemoveHint = $RemoveHint
        Warning = $Warning
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Severity,
        [string]$Confidence,
        [string]$Description,
        [string]$Path,
        [string]$RelativePath,
        [string]$RegistryPath,
        [string]$RegistryName,
        [object]$Value,
        [string]$RecommendedAction,
        [hashtable]$Evidence
    )

    $SeverityScore = Get-SeverityScore -Severity $Severity
    $RiskContribution = Get-RiskContribution -Category $Category -Severity $Severity
    $HardeningContribution = Get-HardeningContribution -Category $Category
    $Remediation = Get-RemediationGuidance -Category $Category -Name $Name -Path $Path -RelativePath $RelativePath -RegistryPath $RegistryPath -RegistryName $RegistryName -Value $Value

    $Item = [ordered]@{
        Category = $Category
        Name = $Name
        Severity = $Severity
        SeverityScore = $SeverityScore
        RiskContribution = $RiskContribution
        HardeningContribution = $HardeningContribution
        Confidence = $Confidence
        Description = $Description
        Path = $Path
        RelativePath = $RelativePath
        RegistryPath = $RegistryPath
        RegistryName = $RegistryName
        Value = $Value
        RecommendedAction = $RecommendedAction
        Remediation = $Remediation
        Evidence = $Evidence
    }

    $Findings.Add($Item) | Out-Null
}

function Add-MarkdownLine {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Text
    )

    $List.Add($Text) | Out-Null
}

function Add-MarkdownField {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Name,
        [object]$Value
    )

    if ($null -eq $Value) {
        return
    }

    $SafeValue = [string]$Value
    $SafeValue = $SafeValue.Replace([char]96, "'")
    $Line = "- " + $Name + " : " + $SafeValue
    $List.Add($Line) | Out-Null
}

$ComputerInfo = $null

try {
    $ComputerInfo = Get-ComputerInfo
}
catch {
    Add-AuditError -Stage "SystemInfo" -Message "Get-ComputerInfo a échoué"
}

$SystemInfo = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    UserDomain = $env:USERDOMAIN
    WindowsProductName = $ComputerInfo.WindowsProductName
    WindowsVersion = $ComputerInfo.WindowsVersion
    WindowsBuild = $ComputerInfo.OsBuildNumber
    Architecture = $env:PROCESSOR_ARCHITECTURE
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    ScanStartedAt = $ScanStartedAt.ToString("yyyy-MM-dd HH:mm:ss")
    ScanMode = if ($DeepScan) { "DeepScan" } else { "Standard" }
    IncludeBrowserCache = [bool]$IncludeBrowserCache
    IncludeNvidiaDetails = [bool]$IncludeNvidiaDetails
    ScriptMode = "Lecture seule"
}

$UninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($UninstallPath in $UninstallPaths) {
    try {
        $Programs = Get-ItemProperty -Path $UninstallPath

        foreach ($Program in $Programs) {
            $ProgramName = $Program.DisplayName

            if ([string]::IsNullOrWhiteSpace($ProgramName)) {
                continue
            }

            $Text = "$($Program.DisplayName) $($Program.Publisher) $($Program.InstallLocation)"
            $MatchedApp = Test-AppNameMatch -Text $Text -Patterns $KnownLocalAiApps

            if ($MatchedApp) {
                Add-Finding -Category "local_ai_tool" -Name $ProgramName -Severity "High" -Confidence "High" -Description "Application IA locale connue détectée dans les programmes installés" -Path $Program.InstallLocation -RelativePath (Get-RelativePathSafe -InputPath $Program.InstallLocation) -RegistryPath $UninstallPath -RegistryName "DisplayName" -Value $ProgramName -RecommendedAction "Vérifier si l’application est voulue. Désinstaller proprement depuis Applications installées si elle n’est pas souhaitée." -Evidence @{
                    MatchedKeyword = $MatchedApp
                    Version = $Program.DisplayVersion
                    Publisher = $Program.Publisher
                    InstallDate = $Program.InstallDate
                }
            }

            if ($IncludeNvidiaDetails -and ($Text -match "NVIDIA AIUser Container")) {
                Add-Finding -Category "nvidia_component" -Name $ProgramName -Severity "Low" -Confidence "Medium" -Description "Composant NVIDIA contenant une mention AI. Généralement lié à l’écosystème NVIDIA et pas forcément à un modèle IA utilisateur." -Path $Program.InstallLocation -RelativePath (Get-RelativePathSafe -InputPath $Program.InstallLocation) -RegistryPath $UninstallPath -RegistryName "DisplayName" -Value $ProgramName -RecommendedAction "Conserver si le pilote NVIDIA est utilisé. Vérifier uniquement si le composant est inattendu." -Evidence @{
                    Version = $Program.DisplayVersion
                    Publisher = $Program.Publisher
                    InstallDate = $Program.InstallDate
                }
            }
        }
    }
    catch {
        Add-AuditError -Stage "InstalledPrograms" -Message "Impossible de lire $UninstallPath"
    }
}

try {
    $Packages = Get-AppxPackage -AllUsers

    foreach ($Package in $Packages) {
        $Text = "$($Package.Name) $($Package.PackageFullName) $($Package.InstallLocation)"
        $MatchedPattern = Test-AppNameMatch -Text $Text -Patterns $WindowsAiAppxPatterns

        if ($MatchedPattern) {
            $Severity = "Medium"
            $Category = "windows_ai_feature"

            if ($Package.Name -match "CoreAI|AIFabric|aimgr") {
                $Category = "confirmed_ai_component"
            }

            Add-Finding -Category $Category -Name $Package.Name -Severity $Severity -Confidence "High" -Description "Paquet Appx Windows lié à l’écosystème IA Microsoft" -Path $Package.InstallLocation -RelativePath (Get-RelativePathSafe -InputPath $Package.InstallLocation) -RegistryPath $null -RegistryName $null -Value $Package.PackageFullName -RecommendedAction "Ne pas supprimer brutalement. Vérifier la fonctionnalité associée et préférer un contrôle par politique." -Evidence @{
                PackageFullName = $Package.PackageFullName
                Publisher = $Package.Publisher
                IsFramework = $Package.IsFramework
                SignatureKind = $Package.SignatureKind
                MatchedPattern = $MatchedPattern
            }
        }
    }
}
catch {
    Add-AuditError -Stage "AppxPackages" -Message "Impossible de lire les paquets Appx"
}

try {
    $Tasks = Get-ScheduledTask

    foreach ($Task in $Tasks) {
        $TaskIdentity = "$($Task.TaskPath)$($Task.TaskName)"

        if ($TaskIdentity -match "\\Microsoft\\Windows\\WindowsAI\\") {
            $Severity = "Medium"

            if ($TaskIdentity -match "\\Recall\\") {
                $Severity = "High"
            }

            Add-Finding -Category "windows_ai_feature" -Name $Task.TaskName -Severity $Severity -Confidence "High" -Description "Tâche planifiée WindowsAI détectée" -Path $TaskIdentity -RelativePath $TaskIdentity -RegistryPath $null -RegistryName $null -Value $Task.State.ToString() -RecommendedAction "Vérifier dans taskschd.msc. Ne pas désactiver sans validation. Documenter l’état et la fonction." -Evidence @{
                TaskPath = $Task.TaskPath
                TaskName = $Task.TaskName
                State = $Task.State.ToString()
                Author = $Task.Author
            }
        }
    }
}
catch {
    Add-AuditError -Stage "ScheduledTasks" -Message "Impossible de lire les tâches planifiées"
}

foreach ($Folder in $KnownAiFolders) {
    $FolderPath = $Folder.Path

    if (Test-Path -Path $FolderPath) {
        $SizeBytes = Get-FolderSizeBytes -InputPath $FolderPath
        $SizeMB = Convert-BytesToMB -Bytes $SizeBytes

        if (($Folder.Category -eq "browser_ai_cache") -and (-not $IncludeBrowserCache)) {
            continue
        }

        Add-Finding -Category $Folder.Category -Name $Folder.Description -Severity $Folder.Severity -Confidence "High" -Description $Folder.Description -Path $FolderPath -RelativePath (Get-RelativePathSafe -InputPath $FolderPath) -RegistryPath $null -RegistryName $null -Value "$SizeMB MB" -RecommendedAction "Vérifier le contenu du dossier. Supprimer uniquement si l’application associée est connue et si une sauvegarde ou validation existe." -Evidence @{
            Exists = $true
            SizeBytes = $SizeBytes
            SizeMB = $SizeMB
        }
    }
}

$SearchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\AppData\Local",
    "$env:USERPROFILE\AppData\Roaming"
)

if ($DeepScan) {
    $SearchRoots += "C:\ProgramData"
    $SearchRoots += "C:\Program Files"
    $SearchRoots += "C:\Program Files (x86)"
}

foreach ($Root in $SearchRoots) {
    if (!(Test-Path -Path $Root)) {
        continue
    }

    try {
        $ExtensionsToSearch = @()
        $ExtensionsToSearch += $HighValueModelExtensions

        if ($IncludeBrowserCache) {
            $ExtensionsToSearch += $WeakModelExtensions
        }

        $Files = Get-ChildItem -Path $Root -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $ExtensionsToSearch -contains $_.Extension.ToLower() }

        foreach ($File in $Files) {
            $FullName = $File.FullName
            $FileName = $File.Name
            $SizeMB = [math]::Round($File.Length / 1MB, 2)

            if (Test-FalsePositivePath -InputPath $FullName -FileName $FileName) {
                continue
            }

            $Category = "local_model_candidate"
            $Severity = "Medium"
            $Confidence = "Medium"
            $Description = "Fichier pouvant correspondre à un modèle local ou à une ressource IA"

            if ($HighValueModelExtensions -contains $File.Extension.ToLower()) {
                $Severity = "High"
                $Confidence = "High"
            }

            if (($File.Extension -ieq ".bin") -and ($SizeMB -lt 10)) {
                continue
            }

            if (($File.Extension -ieq ".bin") -and (-not (Test-AnyKeyword -Text $FullName -Keywords $BrowserAiPaths)) -and (-not (Test-AnyKeyword -Text $FullName -Keywords $OfficeAiPaths))) {
                continue
            }

            if (Test-AnyKeyword -Text $FullName -Keywords $BrowserAiPaths) {
                $Category = "browser_ai_cache"
                $Severity = "Medium"
                $Confidence = "Medium"
                $Description = "Ressource locale navigateur pouvant être liée à une fonctionnalité de suggestion ou optimisation"
            }

            if (Test-AnyKeyword -Text $FullName -Keywords $OfficeAiPaths) {
                $Category = "office_ai_resource"
                $Severity = "Medium"
                $Confidence = "Medium"
                $Description = "Ressource Microsoft Office ou AugLoop pouvant être liée à des fonctionnalités assistées"
            }

            Add-Finding -Category $Category -Name $FileName -Severity $Severity -Confidence $Confidence -Description $Description -Path $FullName -RelativePath (Get-RelativePathSafe -InputPath $FullName) -RegistryPath $null -RegistryName $null -Value "$SizeMB MB" -RecommendedAction "Vérifier le chemin et l’application associée. Ne pas supprimer si le fichier appartient à Chrome, Edge, Office ou une application installée sans validation." -Evidence @{
                Extension = $File.Extension
                SizeBytes = $File.Length
                SizeMB = $SizeMB
                LastWriteTime = $File.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
    catch {
        Add-AuditError -Stage "ModelFileSearch" -Message "Erreur pendant la recherche dans $Root"
    }
}

$ProcessPatterns = @(
    "ollama",
    "lm studio",
    "lmstudio",
    "comfy",
    "stable-diffusion",
    "automatic1111",
    "invokeai",
    "gpt4all",
    "jan",
    "open-webui",
    "localai",
    "kobold"
)

try {
    $Processes = Get-Process

    foreach ($Process in $Processes) {
        $Text = "$($Process.ProcessName) $($Process.Path)"
        $MatchedProcess = Test-AppNameMatch -Text $Text.ToLower() -Patterns $ProcessPatterns

        if ($MatchedProcess) {
            Add-Finding -Category "active_ai_process" -Name $Process.ProcessName -Severity "High" -Confidence "High" -Description "Processus actif lié à un outil IA local connu" -Path $Process.Path -RelativePath (Get-RelativePathSafe -InputPath $Process.Path) -RegistryPath $null -RegistryName $null -Value $Process.Id -RecommendedAction "Vérifier si le processus est voulu. Fermer proprement l’application si elle n’est pas souhaitée." -Evidence @{
                ProcessId = $Process.Id
                CPU = $Process.CPU
                MemoryMB = [math]::Round($Process.WorkingSet64 / 1MB, 2)
            }
        }
    }
}
catch {
    Add-AuditError -Stage "Processes" -Message "Impossible de lire les processus"
}

$ChromePolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKCU:\SOFTWARE\Policies\Google\Chrome"
)

foreach ($PolicyPath in $ChromePolicyPaths) {
    foreach ($PolicyName in $ChromeGenAiPolicies) {
        $Value = Get-RegistryValueSafe -RegistryPath $PolicyPath -Name $PolicyName

        if ($null -ne $Value) {
            Add-Finding -Category "policy_hardening" -Name $PolicyName -Severity "Low" -Confidence "High" -Description "Politique Chrome GenAI détectée" -Path $null -RelativePath $null -RegistryPath $PolicyPath -RegistryName $PolicyName -Value $Value -RecommendedAction "Vérifier dans chrome://policy que la politique est bien appliquée et en état OK." -Evidence @{
                Browser = "Chrome"
                PolicyName = $PolicyName
                PolicyValue = $Value
            }
        }
    }
}

$EdgePolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
)

foreach ($PolicyPath in $EdgePolicyPaths) {
    foreach ($PolicyName in $EdgeAiPolicies) {
        $Value = Get-RegistryValueSafe -RegistryPath $PolicyPath -Name $PolicyName

        if ($null -ne $Value) {
            Add-Finding -Category "policy_hardening" -Name $PolicyName -Severity "Low" -Confidence "High" -Description "Politique Edge liée aux fonctions IA ou Copilot détectée" -Path $null -RelativePath $null -RegistryPath $PolicyPath -RegistryName $PolicyName -Value $Value -RecommendedAction "Vérifier dans edge://policy que la politique est bien appliquée." -Evidence @{
                Browser = "Edge"
                PolicyName = $PolicyName
                PolicyValue = $Value
            }
        }
    }
}

foreach ($Policy in $WindowsAiPolicyChecks) {
    $Value = Get-RegistryValueSafe -RegistryPath $Policy.Path -Name $Policy.Name

    if ($null -ne $Value) {
        $Severity = "Low"
        $Category = "policy_hardening"
        $Description = $Policy.Description

        if ($Value -ne $Policy.ExpectedSecureValue) {
            $Severity = "Medium"
            $Category = "policy_gap"
            $Description = "$($Policy.Description) avec valeur différente de la valeur attendue"
        }

        Add-Finding -Category $Category -Name $Policy.Name -Severity $Severity -Confidence "High" -Description $Description -Path $null -RelativePath $null -RegistryPath $Policy.Path -RegistryName $Policy.Name -Value $Value -RecommendedAction "Vérifier la politique. Une valeur 1 est généralement attendue pour une désactivation quand la politique le prévoit." -Evidence @{
            ExpectedSecureValue = $Policy.ExpectedSecureValue
            CurrentValue = $Value
        }
    }
    else {
        Add-Finding -Category "policy_missing" -Name $Policy.Name -Severity "Medium" -Confidence "Medium" -Description "Politique de contrôle IA absente" -Path $null -RelativePath $null -RegistryPath $Policy.Path -RegistryName $Policy.Name -Value $null -RecommendedAction "Décider si cette politique doit être ajoutée selon la stratégie de durcissement souhaitée." -Evidence @{
            ExpectedSecureValue = $Policy.ExpectedSecureValue
            CurrentValue = $null
        }
    }
}

$GroupedByCategory = @(
    $Findings |
        Group-Object Category |
        ForEach-Object {
            [ordered]@{
                Category = $_.Name
                Count = $_.Count
            }
        }
)

$GroupedBySeverity = @(
    $Findings |
        Group-Object Severity |
        ForEach-Object {
            [ordered]@{
                Severity = $_.Name
                Count = $_.Count
            }
        }
)

$RiskScore = 0
$HardeningScore = 0
$LegacyWeightedScore = 0

foreach ($Finding in $Findings) {
    $RiskScore += $Finding.RiskContribution
    $HardeningScore += $Finding.HardeningContribution
    $LegacyWeightedScore += $Finding.SeverityScore
}

$RiskLevel = "Faible"

if ($RiskScore -ge 25) {
    $RiskLevel = "Moyen"
}

if ($RiskScore -ge 60) {
    $RiskLevel = "Élevé"
}

if ($RiskScore -ge 120) {
    $RiskLevel = "Critique"
}

$ConfirmedCount = ($Findings | Where-Object { $_.Category -in @("confirmed_ai_component", "local_ai_tool", "active_ai_process") }).Count
$WindowsAiCount = ($Findings | Where-Object { $_.Category -eq "windows_ai_feature" }).Count
$PolicyCount = ($Findings | Where-Object { $_.Category -eq "policy_hardening" }).Count
$PolicyGapCount = ($Findings | Where-Object { $_.Category -in @("policy_gap", "policy_missing") }).Count
$ModelCandidateCount = ($Findings | Where-Object { $_.Category -eq "local_model_candidate" }).Count
$BrowserCacheCount = ($Findings | Where-Object { $_.Category -eq "browser_ai_cache" }).Count
$OfficeResourceCount = ($Findings | Where-Object { $_.Category -eq "office_ai_resource" }).Count

$RealityCheck = "Présence IA Windows confirmée. Le score de risque est séparé du score de durcissement. Les politiques protectrices ne gonflent plus le risque."

$ScanEndedAt = Get-Date

$Report = [ordered]@{
    Metadata = [ordered]@{
        ReportName = "AI Integrity Local Audit v2.3"
        GeneratedAt = $ScanEndedAt.ToString("yyyy-MM-dd HH:mm:ss")
        JsonOutputPath = $JsonReportPath
        MarkdownOutputPath = $MarkdownReportPath
        NonDestructive = $true
        DetectionNotice = "Ce rapport énumère des composants potentiellement liés à l’IA. Il ne prouve pas à lui seul une activité malveillante."
        Version = "2.3.0"
    }
    SystemInfo = $SystemInfo
    Summary = [ordered]@{
        TotalFindings = $Findings.Count
        RiskScore = $RiskScore
        HardeningScore = $HardeningScore
        LegacyWeightedScore = $LegacyWeightedScore
        RiskLevel = $RiskLevel
        ConfirmedAiComponents = $ConfirmedCount
        WindowsAiFeatures = $WindowsAiCount
        PolicyHardeningFindings = $PolicyCount
        PolicyGaps = $PolicyGapCount
        LocalModelCandidates = $ModelCandidateCount
        BrowserAiCaches = $BrowserCacheCount
        OfficeAiResources = $OfficeResourceCount
        ErrorCount = $Errors.Count
        RealityCheck = $RealityCheck
    }
    CategorySummary = $GroupedByCategory
    SeveritySummary = $GroupedBySeverity
    Findings = $Findings
    Errors = $Errors
    Recommendations = @(
        "Vérifier les composants WindowsAI et Recall dans le Planificateur de tâches.",
        "Vérifier les politiques Chrome dans chrome://policy.",
        "Vérifier les politiques Edge dans edge://policy si Edge est utilisé.",
        "Ne pas supprimer brutalement les composants CBS, WindowsApps ou SystemApps.",
        "Privilégier les politiques de désactivation plutôt que la suppression manuelle.",
        "Utiliser le bloc Remediation de chaque finding pour savoir où chercher et quoi faire.",
        "Comparer ce rapport avec une future baseline après durcissement."
    )
}

$Report |
    ConvertTo-Json -Depth 14 |
    Out-File -FilePath $JsonReportPath -Encoding UTF8

$Markdown = New-Object System.Collections.Generic.List[string]

Add-MarkdownLine -List $Markdown -Text "# AI Integrity Local Audit v2.3"
Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text "## Résumé"
Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text ("- Total findings : {0}" -f $Report.Summary.TotalFindings)
Add-MarkdownLine -List $Markdown -Text ("- Risk score : {0}" -f $Report.Summary.RiskScore)
Add-MarkdownLine -List $Markdown -Text ("- Hardening score : {0}" -f $Report.Summary.HardeningScore)
Add-MarkdownLine -List $Markdown -Text ("- Legacy weighted score : {0}" -f $Report.Summary.LegacyWeightedScore)
Add-MarkdownLine -List $Markdown -Text ("- Risk level : {0}" -f $Report.Summary.RiskLevel)
Add-MarkdownLine -List $Markdown -Text ("- Confirmed AI components : {0}" -f $Report.Summary.ConfirmedAiComponents)
Add-MarkdownLine -List $Markdown -Text ("- Windows AI features : {0}" -f $Report.Summary.WindowsAiFeatures)
Add-MarkdownLine -List $Markdown -Text ("- Policy hardening findings : {0}" -f $Report.Summary.PolicyHardeningFindings)
Add-MarkdownLine -List $Markdown -Text ("- Policy gaps : {0}" -f $Report.Summary.PolicyGaps)
Add-MarkdownLine -List $Markdown -Text ("- Local model candidates : {0}" -f $Report.Summary.LocalModelCandidates)
Add-MarkdownLine -List $Markdown -Text ("- Browser AI caches : {0}" -f $Report.Summary.BrowserAiCaches)
Add-MarkdownLine -List $Markdown -Text ("- Office AI resources : {0}" -f $Report.Summary.OfficeAiResources)
Add-MarkdownLine -List $Markdown -Text ("- Reality check : {0}" -f $Report.Summary.RealityCheck)
Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text "## Informations système"
Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text ("- ComputerName : {0}" -f $SystemInfo.ComputerName)
Add-MarkdownLine -List $Markdown -Text ("- UserName : {0}" -f $SystemInfo.UserName)
Add-MarkdownLine -List $Markdown -Text ("- WindowsProductName : {0}" -f $SystemInfo.WindowsProductName)
Add-MarkdownLine -List $Markdown -Text ("- WindowsVersion : {0}" -f $SystemInfo.WindowsVersion)
Add-MarkdownLine -List $Markdown -Text ("- WindowsBuild : {0}" -f $SystemInfo.WindowsBuild)
Add-MarkdownLine -List $Markdown -Text ("- ScanMode : {0}" -f $SystemInfo.ScanMode)
Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text "## Synthèse par catégorie"
Add-MarkdownLine -List $Markdown -Text ""

foreach ($Item in $GroupedByCategory) {
    Add-MarkdownLine -List $Markdown -Text ("- {0} : {1}" -f $Item.Category, $Item.Count)
}

Add-MarkdownLine -List $Markdown -Text ""
Add-MarkdownLine -List $Markdown -Text "## Résultats détaillés"
Add-MarkdownLine -List $Markdown -Text ""

foreach ($Finding in $Findings) {
    Add-MarkdownLine -List $Markdown -Text ("### {0}" -f $Finding.Name)
    Add-MarkdownLine -List $Markdown -Text ""
    Add-MarkdownField -List $Markdown -Name "Category" -Value $Finding.Category
    Add-MarkdownField -List $Markdown -Name "Severity" -Value $Finding.Severity
    Add-MarkdownField -List $Markdown -Name "RiskContribution" -Value $Finding.RiskContribution
    Add-MarkdownField -List $Markdown -Name "HardeningContribution" -Value $Finding.HardeningContribution
    Add-MarkdownField -List $Markdown -Name "Confidence" -Value $Finding.Confidence
    Add-MarkdownLine -List $Markdown -Text ("- Description : {0}" -f $Finding.Description)
    Add-MarkdownField -List $Markdown -Name "RelativePath" -Value $Finding.RelativePath
    Add-MarkdownField -List $Markdown -Name "RegistryPath" -Value $Finding.RegistryPath
    Add-MarkdownField -List $Markdown -Name "RegistryName" -Value $Finding.RegistryName
    Add-MarkdownField -List $Markdown -Name "Value" -Value $Finding.Value
    Add-MarkdownLine -List $Markdown -Text ("- RecommendedAction : {0}" -f $Finding.RecommendedAction)
    Add-MarkdownLine -List $Markdown -Text ""
    Add-MarkdownLine -List $Markdown -Text "#### Remediation"
    Add-MarkdownField -List $Markdown -Name "CanDelete" -Value $Finding.Remediation.CanDelete
    Add-MarkdownField -List $Markdown -Name "CanDisable" -Value $Finding.Remediation.CanDisable
    Add-MarkdownField -List $Markdown -Name "Safety" -Value $Finding.Remediation.Safety
    Add-MarkdownField -List $Markdown -Name "Method" -Value $Finding.Remediation.Method
    Add-MarkdownField -List $Markdown -Name "WhereToFind" -Value $Finding.Remediation.WhereToFind
    Add-MarkdownField -List $Markdown -Name "RelativePath" -Value $Finding.Remediation.RelativePath
    Add-MarkdownField -List $Markdown -Name "RegistryPath" -Value $Finding.Remediation.RegistryPath
    Add-MarkdownField -List $Markdown -Name "RegistryName" -Value $Finding.Remediation.RegistryName
    Add-MarkdownField -List $Markdown -Name "CurrentValue" -Value $Finding.Remediation.CurrentValue
    Add-MarkdownField -List $Markdown -Name "DisableHint" -Value $Finding.Remediation.DisableHint
    Add-MarkdownField -List $Markdown -Name "RemoveHint" -Value $Finding.Remediation.RemoveHint
    Add-MarkdownField -List $Markdown -Name "Warning" -Value $Finding.Remediation.Warning
    Add-MarkdownLine -List $Markdown -Text ""
}

$MarkdownText = $Markdown -join [Environment]::NewLine
$MarkdownText | Out-File -FilePath $MarkdownReportPath -Encoding UTF8

Write-Host ""
Write-Host "Audit v2.3 terminé"
Write-Host "Rapport JSON : $JsonReportPath"
Write-Host "Rapport Markdown : $MarkdownReportPath"
Write-Host ""
Write-Host "Résumé"
Write-Host "  Total findings : $($Report.Summary.TotalFindings)"
Write-Host "  Risk score : $($Report.Summary.RiskScore)"
Write-Host "  Hardening score : $($Report.Summary.HardeningScore)"
Write-Host "  Legacy weighted score : $($Report.Summary.LegacyWeightedScore)"
Write-Host "  Risk level : $($Report.Summary.RiskLevel)"
Write-Host "  Confirmed AI components : $($Report.Summary.ConfirmedAiComponents)"
Write-Host "  Windows AI features : $($Report.Summary.WindowsAiFeatures)"
Write-Host "  Policy hardening findings : $($Report.Summary.PolicyHardeningFindings)"
Write-Host "  Policy gaps : $($Report.Summary.PolicyGaps)"
Write-Host "  Local model candidates : $($Report.Summary.LocalModelCandidates)"
Write-Host "  Browser AI caches : $($Report.Summary.BrowserAiCaches)"
Write-Host "  Office AI resources : $($Report.Summary.OfficeAiResources)"
Write-Host ""
Write-Host "Options utiles"
Write-Host "  .\Check-AI-Integrity-v2.3.ps1"
Write-Host "  .\Check-AI-Integrity-v2.3.ps1 -IncludeBrowserCache"
Write-Host "  .\Check-AI-Integrity-v2.3.ps1 -DeepScan -IncludeBrowserCache -IncludeNvidiaDetails"
Write-Host ""

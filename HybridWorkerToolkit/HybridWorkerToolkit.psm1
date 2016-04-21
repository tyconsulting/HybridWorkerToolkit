# .EXTERNALHELP en-US\HybridWorkerToolkit.psm1-Help.xml
Function Get-HybridWorkerConfiguration
{
    #Read Hybrid Worker reg key
    $HybridWorkerRegKeyValues = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker"

    #Get Hybrid worker version
    $SandboxAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-object {$_.ManifestModule.Name -eq 'Orchestrator.Sandbox.exe'}
    If ($SandboxAssembly)
    {
        $HybridWorkerVersion = split-path (split-path (split-path $SandboxAssembly.location)) -leaf
    }

    #Get System Proxy
    $SystemProxyBytes = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings
    $SystemProxyLength = $SystemProxyBytes[12]
    if ($SystemProxyLength -gt 0)
    {
        $SystemProxy = -join ($SystemProxyBytes[(12+3+1)..(12+3+1+$SystemProxyLength-1)] | ForEach-Object {([char]$_)})
    } else {
        $SystemProxy = $null
    }

    #Get MMA configuration
    $MMAConfig = New-Object -ComObject 'AgentConfigManager.MgmtSvcCfg'
    $MMAVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup").AgentVersion
    $HybridWorkerConfig = @{
        HybridWorkerGroupName = $HybridWorkerRegKeyValues.RunbookWorkerGroup
        AutomationAccountId = $HybridWorkerRegKeyValues.AccountId
        MachineId = $HybridWorkerRegKeyValues.MachineId
        ComputerName = $env:COMPUTERNAME
        MMAInstallRoot = $env:MOMROOT
        PSVersion = $host.Version.ToString()
        HybridWorkerVersion = $HybridWorkerVersion
        SystemProxy = $SystemProxy
        MMAVersion = $MMAVersion
        MMAProxyUrl = $MMAConfig.ProxyUrl
        MMAProxyUserName = $MMAConfig.ProxyUsername
        MMAOMSWorkspaceId = $MMAConfig.AzureOperationalInsightsWorkspaceId
    }
    $HybridWorkerConfig
}

# .EXTERNALHELP en-US\HybridWorkerToolkit.psm1-Help.xml
Function Get-HybridWorkerJobRuntimeInfo
{
    #Make sure this function is executed within a runbook
    If ($PSPrivateMetadata -eq $null -and $env:AUTOMATION_ASSET_SANDBOX_ID -eq $null)
    {
        Throw "Get-HybridWorkerJobRuntimeInfo function must be executed within an Azure Automation runbook executed on a Hybrid Worker."
        Exit -1
    }

    #Get job details from Windows event log
    $SandboxId = $env:AUTOMATION_ASSET_SANDBOX_ID
    $5532EventFilter = @"
<QueryList>
    <Query Id='0' Path='Microsoft-SMA/Operational'>
        <Select Path='Microsoft-SMA/Operational'>*[System[(EventID=5532)]] and *[System[(Level=4)]] and *[EventData[Data[@Name='sandboxId']='{$SandboxId}']]</Select>
    </Query>
</QueryList>
"@
    $3732EventFilter = @"
<QueryList>
    <Query Id='0' Path='Microsoft-SMA/Operational'>
        <Select Path='Microsoft-SMA/Operational'>*[System[(EventID=3732)]] and *[System[(Level=4)]] and *[EventData[Data[@Name='sandboxId']='{$SandboxId}']]</Select>
    </Query>
</QueryList>
"@
    #$LogEntry = Get-WinEvent -FilterHashtable $FilterHastable
    $3732LogEntry = Get-WinEvent -FilterXml $3732EventFilter
    $5532LogEntry = Get-WinEvent -FilterXml $5532EventFilter
    $3732LogEntryXML = [XML]$3732LogEntry.ToXml()
    $5532LogEntryXML = [XML]$5532LogEntry.ToXml()
    
    #Convert to hashtable
    $JobEventDetails = @{}
    Foreach ($item in $5532LogEntryXML.Event.EventData.Data)
    {
        $JobEventDetails.Add($Item.Name, $Item.'#text'.Trim("{ }"))
    }

    #Get account name, resource group name and subscription Id
    $RunbookType = ($3732LogEntryXML.Event.EventData.Data | Where-Object {$_.name -ieq 'runbookType'}).'#text'.Trim("{ }")
    $JobEventDetails.Add('RunbookType', $RunbookType)

    $JobInfo = @{
        JobId = $JobEventDetails.JobId;
        SandboxId = $SandboxId
        ProcessId = $PID
        AutomationAssetEndPoint = $env:AUTOMATION_ASSET_ENDPOINT
        PSModulePath = $Env:PSModulePath
        CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        LogActivityTrace = $PSPrivateMetadata.LogActivityTrace
        CurrentWorkingDirectory = $PWD.ToString()
        RunbookType = $JobEventDetails.runbookType
        RunbookName = $JobEventDetails.runbookName
        AccountName = $JobEventDetails.accountName
        ResourceGroupName = $JobEventDetails.resourceGroupName
        SubscriptionId = $JobEventDetails.subscriptionId
        TimeTakenToStartRunninginSeconds = $JobEventDetails.timeTakenToStartRunningInSeconds
    }
    $JobInfo
}

# .EXTERNALHELP en-US\HybridWorkerToolkit.psm1-Help.xml
Function New-HybridWorkerRunbookLogEntry
{
    Param(
        [Parameter(Mandatory=$false,HelpMessage='Please specify the event log name')][Alias('Log')][String]$LogName= 'Application',
        [Parameter(Mandatory=$true,HelpMessage='Please specify the event log ID')][int]$Id,
        [Parameter(Mandatory=$false,HelpMessage='Please specify the event level')][String][ValidateSet('Information', 'Warning', 'Error')]$Level= 'Information',
        [Parameter(Mandatory=$false,HelpMessage='Please specify the event log source')][String][ValidateSet('AzureAutomation Job Verbose', 'AzureAutomation Job Status', 'AzureAutomation Job Result','AzureAutomation Job Process')]$Source = 'AzureAutomation Job Status',
        [Parameter(Mandatory=$false,HelpMessage='Please specify if the Hybrid Worker configuration should be logged in the event log too')][Boolean]$LogHybridWorkerConfig=$false,
        [Parameter(Mandatory=$true,HelpMessage='Please specify the event log message')][String]$Message
    )
    #make sure the event log specified exists
    If (!([System.Diagnostics.EventLog]::Exists($LogName)))
    {
        Throw "the event log specified '$LogName' does not exist. Only administrative event logs are supported."
        Exit -1
    }

    #make sure the event source exists
    if ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false)
    {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $LogName)
    }

    #Determine event level
    Switch ($Level.ToLower())
    {
        'information' {$EventLevel = [System.Diagnostics.EventLogEntryType]::Information}
        'warning' {$EventLevel = [System.Diagnostics.EventLogEntryType]::Warning}
        'error' {$EventLevel = [System.Diagnostics.EventLogEntryType]::Error}
    }

    #Get the runbook runtime info (only if it's not previously retrieved)
    If ($Script:RunbookRuntimeInfo -eq $null)
    {
        $Script:RunbookRuntimeInfo = Get-HybridWorkerJobRuntimeInfo
    }

    #Get the Hybrid Worker configuration (only if it's not previously retrieved)
    If ($Script:HybridWorkerConfig -eq $null)
    {
        $Script:HybridWorkerConfig = Get-HybridWorkerConfiguration
    }

    #Create event log entry
    $evtId = New-Object System.Diagnostics.EventInstance($Id,0,$EventLevel);
    $evtObject = New-Object System.Diagnostics.EventLog;
    $evtObject.Log = $LogName;
    $evtObject.Source = $Source;
    $MessageArray = @()
    $MessageArray += $Message

    #Add environment related info
    $MessageArray += "AutomationAccountName: $($Script:RunbookRuntimeInfo.AccountName)"
    $MessageArray += "HybridWorkerGroupName: $($Script:HybridWorkerConfig.HybridWorkerGroupName)"
    $MessageArray += "ResourceGroupName: $($Script:RunbookRuntimeInfo.ResourceGroupName)"
    $MessageArray += "AzureSubscriptionId: $($Script:RunbookRuntimeInfo.SubscriptionId)"
    If ($LogHybridWorkerConfig -eq $true)
    {
        $MessageArray += "OMSWorkspaceId: $($Script:HybridWorkerConfig.MMAOMSWorkspaceId)"
    }

    #Add agent related info
    If ($LogHybridWorkerConfig -eq $true)
    {
        $MessageArray += "HybridWorkerVersion: $($Script:HybridWorkerConfig.HybridWorkerVersion)"
        $MessageArray += "MMAVersion: $($Script:HybridWorkerConfig.MMAVersion)"
        $MessageArray += "MMAInstallRoot: $($Script:HybridWorkerConfig.MMAInstallRoot)"
        $MessageArray += "MMAProxyUrl: $($Script:HybridWorkerConfig.MMAProxyUrl)"
        $MessageArray += "SystemProxy: $($Script:HybridWorkerConfig.SystemProxy)"
    }

    #Add runbook and job related info
    $MessageArray += "JobId: $($Script:RunbookRuntimeInfo.JobId)"
    $MessageArray += "SandboxId: $($Script:RunbookRuntimeInfo.SandboxId)"
    $MessageArray += "ProcessId: $($Script:RunbookRuntimeInfo.ProcessId)"
    $MessageArray += "CurrentWorkingDirectory: $($Script:RunbookRuntimeInfo.CurrentWorkingDirectory)"
    $MessageArray += "RunbookType: $($Script:RunbookRuntimeInfo.RunbookType)"
    $MessageArray += "RunbookName: $($Script:RunbookRuntimeInfo.RunbookName)"
    $MessageArray += "TimeTakenToStartRunninginSeconds: $($Script:RunbookRuntimeInfo.TimeTakenToStartRunninginSeconds)"

    $evtObject.WriteEvent($evtId, $MessageArray)
}

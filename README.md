# HybridWorkerToolkit

##Description
This repository contains the PowerShell module HybridWorkerToolkit. This PS module is designed to run on Azure Automation Hybrid Workers. It provides various functions that can be called within an Azure Automation runbook when triggered on Hybrid Workers. These activities can assist gathering information about hybrid workers and the runbook runtime environment. It also provides a function to log structured events to the Hybrid Workers Windows Event log.

##PowerShell functions
###Get-HybridWorkerConfiguration
Get the Hybrid Worker and the Microsoft Monitoring Agent configuration. a hashtable is returned with various configuration properties of Hybrid Worker 
and Microsoft Monitoring Agent. It retrieves the following information:
    - Hybrid Worker Group name
    - Automation Account Id
    - Machine Id
    - Computer Name
    - MMA install root
    - PowerShell version
    - Hybrid Worker version
    - System-wide Proxy server address
    - MMA version
    - MMA Proxy URL
    - MMA Proxy user name
    - MMA connected OMS workspace Id

Note: some properties are only returned when this function is called within a Azure automation runbook executed on Hybrid Workers.

###Get-HybridWorkerJobRuntimeInfo
Get the runbook runtime information when executed on a Hybrid Worker. It retrieves the following information:
    - Runbook job ID
    - Sandbox Id
    - Process Id
    - Automation Asset End Point
    - PSModulePath environment variable
    - Current User name
    - Log Activity Trace
    - Current Working Directory
    - Runbook type
    - Runbook name
    - Azure Automation account name
    - Azure Resource Group name
    - Azure subscription Id
    - Time taken to start runbook in seconds
    
###New-HybridWorkerRunbookLogEntry
Create a structured event log entry on the Azure Automation Hybrid Worker.
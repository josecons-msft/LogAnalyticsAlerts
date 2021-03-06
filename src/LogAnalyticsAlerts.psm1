function Get-AccessTokenFromContext
        {
        try {
            $accesstoken = (New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient([Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile)).AcquireAccessToken((Get-AzContext).Subscription.TenantId).AccessToken
            $buildheaders = @{
                'Authorization' = "Bearer $accesstoken"
                'Content-Type' = "application/json"
                        }
            return $buildheaders
            }
        catch
            {
                Write-Output "No context found! Please run 'Login-AzureRMAccount' to login to Azure"
                break
            }
        }
<#
 .Synopsis
  Gets the Log Analytics alerts.

 .Description
  Displays a list Log Analytics alerts, based in the new Azure API, Scheduled
  Query Rules: https://docs.microsoft.com/en-us/rest/api/monitor/scheduledqueryrules
  This function currently does not take any parameters, so it will display all
  the alerts for the past 24h, for the current subscription.

  For further information on the new API (SQR), please review this document:
  https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-log-api-switch

 .Example
   Get-LogAnalyticsAlerts
   # This command will show all the Log Analytics alerts (Log and Metric) of the current subscription, of the last 24 hours.
#>
function Get-LogAnalyticsAlerts
    {
    param(
         )
        $headers = Get-AccessTokenFromContext
        $cur_sub = (Get-AzContext).Subscription.Id
        $ruleidURI = "https://management.azure.com/subscriptions/$cur_sub/providers/Microsoft.AlertsManagement/alerts" + "?api-version=2018-05-05&targetResourceType=Microsoft.OperationalInsights/workspaces"
        $laAlerts = (Invoke-RestMethod -Method GET $ruleidURI -Headers $headers).value
        $laAlerts | Select-Object name,@{Name="Sev.";Expression={$_.properties.essentials.severity}}, @{Name="MonitorCondition";Expression={$_.properties.essentials.monitorCondition}}, @{Name="State";Expression={$_.properties.essentials.alertState}},@{Name="Workspace";Expression={$_.properties.essentials.targetResourceName}}, @{Name="MonitorService";Expression={$_.properties.essentials.monitorService}} ,@{Name="SignalType";Expression={$_.properties.essentials.signalType}} ,@{Name="StartTime";Expression={$_.properties.essentials.startDateTime}},@{Name="LastModifiedTime";Expression={$_.properties.essentials.lastModifiedDateTime}},@{Name="MonitorResolvedTime";Expression={$_.properties.essentials.monitorConditionResolvedDateTime}} | Format-Table -AutoSize -Wrap
    }

<#
 .Synopsis
  Gets the Log Analytics alert rules.

 .Description
  Displays a list Log Analytics alerts rule, based in the new Azure API, Scheduled
  Query Rules: https://docs.microsoft.com/en-us/rest/api/monitor/scheduledqueryrules
  This function currently does not take any parameters, so it will display all
  the alert rules of the current subscription.

  For further information on the new API (SQR), please review this document:
  https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-log-api-switch

 .Example
   Get-LogAnalyticsAlertRule
   # This command will show all the Log Analytics SQR alert rules based of the current subscription.
#>
function Get-LogAnalyticsAlertRule
    {
    param(
         )
        $headers = Get-AccessTokenFromContext
        $cur_sub = (Get-AzContext).Subscription.Id
        $ruleidURI = "https://management.azure.com/subscriptions/$cur_sub/providers/microsoft.insights/scheduledQueryRules" + "?api-version=2018-04-16"
        $sqrs = (Invoke-RestMethod -Method GET $ruleidURI -Headers $headers).value
        #$sqrs | Select-Object @{Name="DisplayName";Expression={$_.properties.displayname}},@{Name="IsEnabled";Expression={$_.properties.enabled}}, @{Name="LastModified";Expression={$_.properties.lastUpdatedTime}},@{Name="Workspace";Expression={[regex]::Match($_.properties.source.dataSourceId,"(?<=\/workspaces\/)(.*)").value}},@{Name="Resource Group";Expression={[regex]::Match($_.properties.source.dataSourceId,"(?<=\/resourceGroups\/)(.*)(?=\/providers)").value}} | Format-Table
        $sqrs | Select-Object name, @{Name="DisplayName";Expression={$_.properties.displayname}},@{Name="IsEnabled";Expression={$_.properties.enabled}},@{Name="Workspace";Expression={[regex]::Match($_.properties.source.dataSourceId,"(?<=\/workspaces\/)(.*)").value}},@{Name="Resource Group";Expression={[regex]::Match($_.properties.source.dataSourceId,"(?<=\/resourceGroups\/)(.*)(?=\/providers)").value}} | Format-Table -AutoSize -Wrap
    }

<#
 .Synopsis
  Enables a Log Analytics alert rule.

 .Description
  Enables a Log Analytics alert rule, based on the rule name and the resource
  group name where the alert rule is contained. As the rule name may not
  match the display name, please run the 'Get-LogAnalyticsAlertRule' cmdlet
  to get the correct alert rule name.

 .Example
   Enable-LogAnalyticsAlertRule -rulename "Dev machine is running out of memory" -ResourceGroupName "mms-weu"
   # This command will enable the rule named "Dev machine is running out of memory" that
   # is contained on the "mms-weu" resource group of the current subscription.
#>
function Enable-LogAnalyticsAlertRule
{
    param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $Rulename,
        [Parameter(Position=1,mandatory=$true)]
        [string] $ResourceGroupName)

        $headers = Get-AccessTokenFromContext
        $cur_sub = (Get-AzContext).Subscription.Id
        $ruleUri = "https://management.azure.com/subscriptions/$cur_sub/resourcegroups/$resourceGroupName/providers/microsoft.insights/scheduledQueryRules/$RuleName"+"?api-version=2018-04-16"
        $bodyEnable = "
        {
            'properties': {
              'enabled': 'true'
            }
          }
        "
        Write-Verbose "ResourceURI being invoked: $ruleUri"
         try
            {
                $enablerule = Invoke-RestMethod -Method PATCH -Uri $ruleUri -Headers $headers -Body $bodyEnable
                $enablerule | Select-Object @{Name="displayName";Expression={$_.properties.displayName}}, @{Name="IsEnabled";Expression={$_.properties.enabled}},@{Name="lastUpdate";Expression={$_.properties.lastUpdatedTime}}, @{Name="provisioningState";Expression={$_.properties.provisioningState}} | Format-Table -AutoSize -Wrap
                Write-Verbose "Output of Invoke-RestMethod: $enablerule"
            }
         catch
            {
                Write-Error "$_"
            }
     }

<#
 .Synopsis
  Disables a Log Analytics alert rule.

 .Description
  Disables a Log Analytics alert rule, based on the rule name and the resource
  group name where the alert rule is contained. As the rule name may not
  match the display name, please run the 'Get-LogAnalyticsAlertRule' cmdlet
  to get the correct alert rule name.

 .Example
   Disable-LogAnalyticsAlertRule -rulename "Dev machine is running out of memory" -ResourceGroupName "mms-weu"
   # This command will disable the rule named "Dev machine is running out of memory" that
   # is contained on the "mms-weu" resource group of the current subscription.
#>
function Disable-LogAnalyticsAlertRule
     {
         param(
             [Parameter(Position=0,mandatory=$true)]
             [string] $Rulename,
             [Parameter(Position=1,mandatory=$true)]
             [string] $ResourceGroupName)

             $headers = Get-AccessTokenFromContext
             $cur_sub = (Get-AzContext).Subscription.Id
             $ruleUri = "https://management.azure.com/subscriptions/$cur_sub/resourcegroups/$resourceGroupName/providers/microsoft.insights/scheduledQueryRules/$RuleName"+"?api-version=2018-04-16"
             $bodyEnable = "
             {
                 'properties': {
                   'enabled': 'false'
                 }
               }
             "
             Write-Verbose "ResourceURI being invoked: $ruleUri"
              try {
                $disablerule = Invoke-RestMethod -Method PATCH -Uri $ruleUri -Headers $headers -Body $bodyEnable
                $disablerule | Select-Object @{Name="displayName";Expression={$_.properties.displayName}}, @{Name="IsEnabled";Expression={$_.properties.enabled}},@{Name="lastUpdate";Expression={$_.properties.lastUpdatedTime}}, @{Name="provisioningState";Expression={$_.properties.provisioningState}} | Format-Table -AutoSize -Wrap
                Write-Verbose "Output of Invoke-RestMethod: $disablerule"
                 }
              catch
                 {
                    Write-Error "$_"
                 }
          }

<#
 .Synopsis
  Switches a Log Analytics workspace to the new Log Alerts API.

 .Description
  Switches a Log Analytics workspace to the new Log Alerts API, so you can use
  all the cmdlets of this module and/or manage your Log Analytics alerts using
  the new Scheduled Query Rules API. This is an irreversible action, so please
  review the following document before proceeding:
  https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-log-api-switch

 .Example
   Enable-LogAnalyticsAlertsNewAPI -WorkspaceName "joselindo" -ResourceGroupName "joseRG"
   # This command will prompt you to switch the workspace names "joselindo" that is
   # contained on the "joseRG" resource group to use the new Azure API, Scheduled Query Rules.
   # Once prompt, you will have to type the word "YES" to confirm the switch.
   
   # Enable-LogAnalyticsAlertsNewAPI -WorkspaceName "joselindo" -ResourceGroupName "joseRG" -Force
   # This command will switch the workspace names "joselindo" that is contained on the "joseRG"
   # resource group to use the new Azure API, Scheduled Query Rules, without any user prompt.
   # Using the -Force switch implies you have read the API switch document
#>
function Enable-LogAnalyticsAlertsNewAPI
        {
              param(
                  [Parameter(Position=0,mandatory=$true)]
                  [string] $WorkspaceName,
                  [Parameter(Position=1,mandatory=$true)]
                  [string] $ResourceGroupName,
				  [switch] $Force)

				  $Readhost = "No"
                  $headers = Get-AccessTokenFromContext
                  $cur_sub = (Get-AzContext).Subscription.Id
                  $workspaceURI = "https://management.azure.com/subscriptions/$cur_sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/alertsversion" + "?api-version=2017-04-26-preview"
                  Write-Verbose "WorkspaceURI being invoked: $workspaceURI"
                  <#Let's check if the new API is enabled; if so, no need to make the PATCH call#>
				  try {
                    $isInabled = Invoke-RestMethod -Method GET $workspaceURI -Headers $headers
                    Write-Verbose "Output of Invoke-RestMethod: $disablerule"
                     }
                  catch
                     {
                        Write-Error "$_"
                        break
                     }
                  if ( $isInabled.scheduledQueryRulesEnabled)
                  {
                    Write-Output "New SQR API is already enabled for workspace $workspaceName in resource group $ResourceGroupName"
                      break
                  }
				  <#Checking if -Force parameter was used#>
				  	if ($Force -ne $true)
					  {
							<#Informing that this is a irreversible action and that they should check the documentaiont before proceeding#>
							Write-Output "This is an irreversible action, so please sure you have read the following doc: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-log-api-switch#process-of-switching-from-legacy-log-alerts-api"
							Write-Output "Please type YES to continue? (Default is NO)"
							$Readhost = Read-Host " ( YES / NO ) "
					  }

                  If ( ($Readhost.Trim().ToUpper() -eq "YES") -or ($Force -eq $true))
                                          {
                                             $jsonpayload =  '{"scheduledQueryRulesEnabled": true}'
                                             try {
                                                $enableSQR = Invoke-RestMethod -Method PUT $workspaceURI -Headers $headers -Body $jsonpayload
                                                Write-Verbose "Output of Invoke-RestMethod: $enableSQR"
                                                Write-Output "Changes were applied!"
                                                 }
                                              catch
                                                 {
                                                    Write-Error "$_"
                                                    break
                                                 }
                                          }
                  else {Write-Output "No changes were applied!"}
        }

Export-ModuleMember -Function Get-LogAnalyticsAlerts
Export-ModuleMember -Function Get-LogAnalyticsAlertRule
Export-ModuleMember -Function Enable-LogAnalyticsAlertRule
Export-ModuleMember -Function Disable-LogAnalyticsAlertRule
Export-ModuleMember -Function Enable-LogAnalyticsAlertsNewAPI

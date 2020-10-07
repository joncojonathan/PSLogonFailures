# PSLogonFailures.ps1 v1.6.1, 2013-01-26
# Working with 2008 R1 since 22nd November 2012.
# (Formerly SecurityLog_LogonFailures.ps1)
# Obtain Errors logging on (id = 4625) and then block the IP of the source host if above the specified threshold
# Jonathan Haddock
# www.jonsdocs.org.uk
# Andrew Cassidy (initial script creation)
# www.cassidywebservices.co.uk
# This script is provided with NO WARRANTIES of any kind and the authors CANNOT be held liable for any losses or damages incurred as a result of using this script.
# You may distribute this script as per the terms of the GNU GPL license, however, the attribution block above must be preserved.

$LogName = "Security"
$WriteLogSource = "PSLogonFailures"
$WriteLog = "Application"
$WriteLogStart = 1
$WriteLogEnd = 1
$minutes = 30
$threshold = 4

#Choose what services to block (RDP is blocked by default based on $RDPPort).
$RDPPort=3389
$BlockAll = 0 # Blocks all TCP ports, 1-65535
$BlockWeb = 0 # Set to 1 to block HTTP and HTTPS (80 and 443)
$BlockSMTP = 0 # Set to 1 blocks SMTP traffic on port 25
$BlockRWW_RDP = 0 # When set to 1, blocks port 4125, used by SBS servers to proxy RDP connections.
$fwprofile = "Any" # Set to "Any" to apply to all networks (public, domain, private / home)

# Full path to the allowList, e.g. c:\psl\allowList.txt :
$allowList = 'C:\psl\allowList.txt'
# Full path to blockList e.g: c:\psl\blockList.txt
$blockList = 'C:\psl\blockList.txt'

############################
# Do not edit beneath here #
############################
#Determine Windows Version:
$WinVer = [System.Environment]::OSVersion.Version

#Deal with the lists:
$blockList = @{}

if (test-path $allowList) { 
	write-host "allowList found" -foregroundcolor green
	} else {
		# If the allowList can't be found:
		Write-host "Unable to find the allowList file, exiting for your protection." -foregroundcolor red -backgroundcolor gray
		Write-EventLog -LogName $WriteLog -Message "PSLogonFailures.ps1 cannot load the allowList.  Exiting for your protection. `n allowList claims to be at: $allowList" -Source $WriteLogSource -EntryType Error -id 1237
		exit
	}


# Function to delete all firewall rules
function DeletePSLFirewallRules {
	write-host Deleting PSLogonFailures firewall rules...
	netsh advfirewall firewall del rule name="PSLogonFailures - Block RDP"
	netsh advfirewall firewall del rule name="PSLogonFailures - Block Web"
	netsh advfirewall firewall del rule name="PSLogonFailures - Block SMTP"
	netsh advfirewall firewall del rule name="PSLogonFailures - Block RWW-RDP"
	netsh advfirewall firewall del rule name="PSLogonFailures - Block All TCP"
}

function ProcessblockLists {
	write-host Processing blockLists -foregroundcolor yellow
	if (test-path $blockList){
		if ((get-content $blockList|measure-object).count -gt 0){
			#Add the blockList to the $blockList
			$blockList_content = get-content $blockList
			foreach ($BlIP in $blockList_content){
				if($blockList.ContainsKey($BlIP)){
						$blockList[$BlIP] = $blockList[$BlIP]+1
				}else{
						$blockList.add($BlIP, $threshold)
				}
			}	
		}
	} else {
		Write-EventLog -LogName $WriteLog -Message "PSLogonFailures.ps1 cannot load the blockList.`n blockList claims to be at: $blockList" -Source $WriteLogSource -EntryType Error -id 1239
	}
	
}

function ProcessallowList{
	write-host Processing allowList -foregroundcolor yellow
	$allowListIPs = get-content $allowList
	foreach ($ip in $allowListIPs)
	{
		if ($blockList.containskey($ip)){
			$badwhites = "$badwhites `n $ip"
			$blockList.remove($ip)
		}
	}
}

function AddFirewallRules {
	$remoteIPS = New-Object System.Text.StringBuilder
	foreach ($attempt in $blockList.keys){
    	if ($blockList[$attempt] -ge $threshold){
			[void]($remoteIPs.appendformat("{0},",$attempt))
		}

	}

    $remoteIPs = $remoteIPs.tostring().trim(',')

	# Use netsh to adjust firewalls:
	# See http://support.microsoft.com/kb/947709

	#Unblock the IPs (call the function):
	DeletePSLFirewallRules

	$BlockedServices = " from "
	# Determine what services whould have been blocked:
	if ($BlockAll -eq 1){
		$BlockedServices = "$BlockedServices All TCP (ports 1 - 65535)"
	} else {
		$BlockedServices = "$BlockedServices RDP (on $RDPPort)"
		if ($BlockWeb -eq 1){
			$BlockedServices = "$BlockedServices , Web (HTTP, HTTPS)"
		} 
			
		if ($BlockSMTP -eq 1){
			$BlockedServices = "$BlockedServices , SMTP"
		} 
			
		if ($BlockRWW_RDP -eq 1){
			$BlockedServices = "$BlockedServices , RWW-RDP (4125)"
		} 
	}
	
	# Block services if there were remote IPs:
	if ($remoteIPs){   
	   if ($BlockAll -eq 1){
		netsh advfirewall firewall add rule name="PSLogonFailures - Block All TCP" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=Any
	   } else {
		# If not blocking all TCP ports, perform other checks.
		   netsh advfirewall firewall add rule name="PSLogonFailures - Block RDP" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=$RDPPort
			
			# Block additional services based on preference:
			if ($BlockWeb -eq 1){
				netsh advfirewall firewall add rule name="PSLogonFailures - Block Web" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=80
				netsh advfirewall firewall add rule name="PSLogonFailures - Block Web" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=443
			} 
			
			if ($BlockSMTP -eq 1){
				netsh advfirewall firewall add rule name="PSLogonFailures - Block SMTP" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=25
			} 
			
			if ($BlockRWW_RDP -eq 1){
				netsh advfirewall firewall add rule name="PSLogonFailures - Block RWW-RDP" dir=in action=block profile=$fwprofile remoteip="$remoteIPs" protocol=TCP localport=4125
			} 
		
		}#End block if not all.
			
	} 
		
		if ($remoteIPs -or $badwhites){
			$WriteLogID = 1236
			$WriteLogType = 'Error'
			if (!$remoteIPs){
				$remoteIPs = 'None'
			}
		} else {
			$remoteIPs = 'None'
			$BlockedServices = ''
			$WriteLogID = 1235
			$WriteLogType = 'Information'
			$badwhites = 'none'
		}
		
}

function BlockblockListOnly {
	#This will be called if the local security log doesn't have any failed logins.
	. ProcessblockLists
	. ProcessallowList
	. AddFirewallRules
	
}

function WriteEndLog{
	if ($WriteLogEnd -eq 1){
		if ($WriteLogType -eq 'Error'){
			Write-EventLog -LogName $WriteLog -Message "Finished PSLogonFailures.ps1.`nThe following IPs were blocked $BlockedServices : `n $remoteIPs `n The following allowListed IPs are also attacking (or on a blockList): $badwhites `n allowList file: $allowList" -EntryType $WriteLogType -Source $WriteLogSource -id $WriteLogID
		} else {
			Write-EventLog -LogName $WriteLog -Message "Finished PSLogonFailures.ps1.  There were no failed logon attempts in the security log.  Removing the firewall rule." -Source $WriteLogSource -id $WriteLogID
		}
	}  

}

$ErrorActionPreference = 'Stop'

trap [Exception]
{
    if ($_.FullyQualifiedErrorId -eq 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand')
    {
        write-host "No Entries (TRAP)"
  
        DeletePSLFirewallRules
		. BlockblockListOnly
		WriteEndLog
        exit
    } else { 
		throw $_ 
	}
}



if ($WriteLogStart -eq 1){
    # Log the fact this script is starting.
    Write-EventLog -LogName $WriteLog -Message "Starting PSLogonFailures.ps1.  `n Windows Version $WinVer .  `n Your allowList: $allowList" -Source $WriteLogSource -id 1234
}

$interval = (get-date) - (new-timespan -minutes $minutes)

if ($WinVer.major -eq 6 -and $WinVer.minor -eq 0){
    $event = get-eventlog -logname $LogName -After $interval |where {$_.instanceid -eq 4625}
} else {
    $event = get-winevent -FilterHashtable @{ logname=$LogName; ID=4625; StartTime=$interval }
}

#Add the blockList to the $blockList
ProcessblockLists

    foreach ($ip in $event){
    
	  $value = $ip.message|select-string -Pattern "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"|Select-Object matches
	
	  #If we're on 2008 it's likely we're going to get a bad EventLog message ("The description for....")
	  $check = $ip.message|select-string -Pattern "The description+"|Select-Object matches
	  
      if($check.matches){
		#If this has the problem:
		$value2 = $ip.message|select-string -Pattern "'10'"|Select-Object matches
	  } else {
		#If this is a working system:
		$value2 = $ip.message|select-string -Pattern "Logon Type:[ \t]+10"|Select-Object matches
	  }
      
      if ($value.matches -and $value2.matches){
        $BadIP = $value.matches[0].value
       
       
       if($blockList.ContainsKey($BadIP)){
            $blockList[$BadIP] = $blockList[$BadIP]+1
       }else{
            $blockList.add($BadIP, 1)
       }

     }
    
}

# Deal with the allowList
. ProcessallowList
# Remove any stale rules
. DeletePSLFirewallRules
# Block attackers to this server and those on the blockList:
. AddFirewallRules
WriteEndLog

#if ($WriteLogEnd -eq 1){
#    Write-EventLog -LogName $WriteLog -Message "Finished PSLogonFailures.ps1.`nThe following IPs were blocked $BlockedServices : `n $remoteIPs `n The following allowListed IPs are also attacking: $badwhites `n allowList file: $allowList" -EntryType $WriteLogType -Source $WriteLogSource -id $WriteLogID
#}

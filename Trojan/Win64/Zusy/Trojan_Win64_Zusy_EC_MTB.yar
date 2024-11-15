
rule Trojan_Win64_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d0 48 c1 e8 02 48 31 d0 48 89 c2 48 c1 ea 15 48 31 c2 48 89 d0 48 c1 e8 16 48 31 d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 6c 6c 69 6e 67 21 } //2 Balling!
		$a_01_1 = {37 39 2e 31 37 34 2e 39 32 2e 32 32 } //2 79.174.92.22
		$a_01_2 = {46 61 74 61 6c 20 65 72 72 6f 72 20 69 6e 20 68 6f 73 74 20 6e 61 6d 65 20 72 65 73 6f 6c 76 69 6e 67 } //2 Fatal error in host name resolving
		$a_01_3 = {48 89 44 24 30 48 c7 44 24 48 87 69 00 00 48 c7 44 24 40 84 03 00 00 b9 02 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule Trojan_Win64_Zusy_EC_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {30 41 66 51 52 50 31 64 68 74 34 61 52 51 6f 33 31 66 6a 51 4f 37 43 33 4d 75 4e 48 77 6c 7a 4e 4f 67 78 31 5a 41 67 3d 3d } //1 0AfQRP1dht4aRQo31fjQO7C3MuNHwlzNOgx1ZAg==
		$a_81_1 = {57 56 59 33 4b 5a 6e 70 69 46 56 7a 6c 74 48 62 46 6c 72 35 55 32 5a 33 30 54 32 6c 6c 51 42 31 5a 4b 6b 55 47 63 4a 56 51 46 78 74 4e 57 32 4e 4c 31 52 33 70 70 5a 5a 68 70 57 44 53 6c 4a 68 44 46 46 31 63 46 61 56 78 6a 57 56 6b 64 33 4a 61 57 59 48 37 58 77 3d 3d } //1 WVY3KZnpiFVzltHbFlr5U2Z30T2llQB1ZKkUGcJVQFxtNW2NL1R3ppZZhpWDSlJhDFF1cFaVxjWVkd3JaWYH7Xw==
		$a_81_2 = {56 57 68 42 39 61 30 4a 51 79 4d 48 59 31 44 65 57 4a 54 36 65 54 52 31 4e 63 42 4d 75 65 42 79 30 45 45 46 6e 59 77 4c 47 44 38 6b 6f 46 54 38 5a 41 4d 7a 59 54 58 4c 6d 77 74 6b 42 42 5a 32 45 57 33 4d 2f 37 4a 42 55 2f 47 63 6a 4d 32 72 45 79 34 48 5a 4c 51 3d 3d } //1 VWhB9a0JQyMHY1DeWJT6eTR1NcBMueBy0EEFnYwLGD8koFT8ZAMzYTXLmwtkBBZ2EW3M/7JBU/GcjM2rEy4HZLQ==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win64_Zusy_EC_MTB_4{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 65 73 61 63 74 69 76 61 64 6f 20 49 6e 74 65 72 6e 65 74 21 } //1 Desactivado Internet!
		$a_81_1 = {53 74 72 65 61 6d 20 4d 6f 64 65 20 20 44 45 53 41 43 54 49 56 41 44 4f } //1 Stream Mode  DESACTIVADO
		$a_81_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 } //1 netsh advfirewall firewall delete rule name
		$a_81_3 = {4e 4f 53 4b 49 4c 4c 20 52 41 46 41 2e 70 64 62 } //1 NOSKILL RAFA.pdb
		$a_81_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_81_5 = {54 72 61 63 6b 4d 6f 75 73 65 45 76 65 6e 74 } //1 TrackMouseEvent
		$a_81_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_7 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_81_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_9 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}
rule Trojan_Win64_Zusy_EC_MTB_5{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 43 6f 6d 6d 61 6e 64 } //1 powershell.exe-Command
		$a_81_1 = {24 74 61 73 6b 73 20 3d 20 47 65 74 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 20 7b } //1 $tasks = Get-ScheduledTask | Where-Object {
		$a_81_2 = {66 6f 72 65 61 63 68 20 28 24 74 61 73 6b 20 69 6e 20 24 74 61 73 6b 73 29 20 7b } //1 foreach ($task in $tasks) {
		$a_81_3 = {43 6c 65 61 72 2d 52 65 63 79 63 6c 65 42 69 6e 20 2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //1 Clear-RecycleBin -Force -ErrorAction SilentlyContinueC:\Users\Public
		$a_81_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 55 53 45 52 50 52 4f 46 49 4c 45 46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 55 53 45 52 50 52 4f 46 49 4c 45 } //1 C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartupUSERPROFILEFailed to get USERPROFILE
		$a_81_5 = {24 62 75 66 66 65 72 5b 24 63 6f 75 6e 74 5d 20 3d 20 5b 62 79 74 65 5d 28 24 74 65 6d 70 46 69 6c 65 73 5b 24 69 5d 29 } //1 $buffer[$count] = [byte]($tempFiles[$i])
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
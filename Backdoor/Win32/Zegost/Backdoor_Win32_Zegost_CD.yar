
rule Backdoor_Win32_Zegost_CD{
	meta:
		description = "Backdoor:Win32/Zegost.CD,SIGNATURE_TYPE_PEHSTR,34 00 34 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 64 6c 6c } //0a 00  svchost.dll
		$a_01_1 = {6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 } //0a 00  kaspersky
		$a_01_2 = {47 00 68 00 30 00 73 00 74 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 } //0a 00  Gh0st Update
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //0a 00  CreateRemoteThread
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_5 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 57 } //01 00  OpenSCManagerW
		$a_01_6 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 30 } //01 00  GET %s HTTP/1.0
		$a_01_7 = {25 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  %s\shell\open\command
		$a_01_8 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  Applications\iexplore.exe\shell\open\command
		$a_01_9 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		any of ($a_*)
 
}
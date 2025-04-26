
rule Backdoor_Win32_BazarLoader_MTB{
	meta:
		description = "Backdoor:Win32/BazarLoader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_81_1 = {4e 6f 52 75 6e } //1 NoRun
		$a_81_2 = {4e 6f 44 72 69 76 65 73 } //1 NoDrives
		$a_81_3 = {52 65 73 74 72 69 63 74 52 75 6e } //1 RestrictRun
		$a_81_4 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_81_5 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 NoRecentDocsHistory
		$a_81_6 = {4e 6f 43 6c 6f 73 65 } //1 NoClose
		$a_81_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Network
		$a_81_8 = {4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b } //1 NoEntireNetwork
		$a_81_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 43 6f 6d 64 6c 67 33 32 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Comdlg32
		$a_01_10 = {34 00 30 00 39 00 36 00 } //1 4096
		$a_01_11 = {4e 00 54 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00 } //1 NTDLL.dll
		$a_01_12 = {46 75 63 6b 20 44 65 66 } //1 Fuck Def
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
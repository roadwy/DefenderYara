
rule TrojanDownloader_Win32_Sysrus_A{
	meta:
		description = "TrojanDownloader:Win32/Sysrus.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 76 00 69 00 72 00 75 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  C:\Windows\system32\virus.exe
		$a_01_1 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 76 00 69 00 72 00 75 00 73 00 } //01 00  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\virus
		$a_01_2 = {66 00 3a 00 2f 00 2a 00 2e 00 2a 00 } //01 00  f:/*.*
		$a_01_3 = {46 00 3a 00 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  F:/autorun.inf
		$a_01_4 = {67 00 3a 00 2f 00 2a 00 2e 00 2a 00 } //01 00  g:/*.*
		$a_01_5 = {47 00 3a 00 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  G:/autorun.inf
		$a_01_6 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //00 00  WScript.Shell
	condition:
		any of ($a_*)
 
}
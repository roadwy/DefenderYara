
rule TrojanDownloader_Win32_Agent_IW{
	meta:
		description = "TrojanDownloader:Win32/Agent.IW,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 3f 64 61 74 61 3d } //01 00 
		$a_00_1 = {4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 } //01 00  Msxml2.DOMDocument
		$a_00_2 = {53 6f 6d 65 66 6f 78 } //01 00  Somefox
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 2f 73 69 7a 65 2e 70 68 70 90 00 } //01 00 
		$a_00_4 = {53 6e 6d 70 45 78 74 65 6e 73 69 6f 6e 54 72 61 70 } //01 00  SnmpExtensionTrap
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_00_7 = {22 20 3e 20 6e 75 6c 20 32 3e 20 6e 75 6c } //01 00  " > nul 2> nul
		$a_00_8 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 53 6f 6d 65 66 6f 78 } //00 00  HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\Somefox
	condition:
		any of ($a_*)
 
}
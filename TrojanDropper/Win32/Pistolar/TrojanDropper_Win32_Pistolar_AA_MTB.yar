
rule TrojanDropper_Win32_Pistolar_AA_MTB{
	meta:
		description = "TrojanDropper:Win32/Pistolar.AA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  \svhost.exe
		$a_01_1 = {6b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 } //01 00  kaspersky
		$a_01_2 = {76 00 69 00 72 00 75 00 74 00 } //01 00  virut
		$a_01_3 = {74 00 72 00 6f 00 6a 00 61 00 6e 00 } //01 00  trojan
		$a_01_4 = {61 00 6e 00 74 00 69 00 2d 00 76 00 69 00 72 00 75 00 73 00 } //01 00  anti-virus
		$a_01_5 = {6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //01 00  malware
		$a_01_6 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 54 00 61 00 73 00 6b 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //01 00  Windows Task Manager
		$a_01_7 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 2e 00 64 00 62 00 } //00 00  \Driver.db
	condition:
		any of ($a_*)
 
}
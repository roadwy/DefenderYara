
rule Trojan_BAT_Babadeda_RDA_MTB{
	meta:
		description = "Trojan:BAT/Babadeda.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 79 54 72 6f 6a } //01 00  WeyTroj
		$a_01_1 = {57 00 65 00 79 00 54 00 30 00 30 00 78 00 2e 00 74 00 6d 00 70 00 } //01 00  WeyT00x.tmp
		$a_01_2 = {72 00 75 00 6e 00 30 00 30 00 2e 00 65 00 78 00 65 00 } //01 00  run00.exe
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } //01 00  DisableRegistryTools
		$a_01_5 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 53 00 4c 00 6f 00 67 00 2e 00 64 00 6c 00 6c 00 } //00 00  System32\WSLog.dll
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_Win32_VB_IN{
	meta:
		description = "TrojanDropper:Win32/VB.IN,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 79 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  ayhost.exe
		$a_01_1 = {62 00 61 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  bahost.exe
		$a_01_2 = {63 00 73 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  cshost.exe
		$a_01_3 = {64 00 6a 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  djhost.exe
		$a_01_4 = {65 00 6b 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  ekhost.exe
		$a_01_5 = {66 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  flhost.exe
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_BAT_VB_C{
	meta:
		description = "TrojanDropper:BAT/VB.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 42 00 46 00 69 00 6c 00 65 00 31 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {5c 00 42 00 46 00 69 00 6c 00 65 00 32 00 2e 00 6a 00 70 00 67 00 } //01 00 
		$a_01_2 = {44 3a 5c 55 73 65 72 73 5c 50 65 74 65 72 5c 44 65 73 6b 74 6f 70 5c 53 74 75 62 5c 53 74 75 62 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 74 75 62 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
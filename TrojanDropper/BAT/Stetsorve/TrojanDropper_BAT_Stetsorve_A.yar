
rule TrojanDropper_BAT_Stetsorve_A{
	meta:
		description = "TrojanDropper:BAT/Stetsorve.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f 1c 28 06 00 00 0a 72 01 00 00 70 06 20 10 27 00 00 20 3f 42 0f 00 6f 07 00 00 0a 13 0b 12 0b 28 08 00 00 0a 72 05 00 00 70 28 09 00 00 0a 0d 08 } //01 00 
		$a_01_1 = {2e 65 78 65 00 5f 4d 61 69 6e 00 43 4f 4c 44 } //00 00 
	condition:
		any of ($a_*)
 
}
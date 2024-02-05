
rule TrojanDropper_BAT_Vobfus_A{
	meta:
		description = "TrojanDropper:BAT/Vobfus.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {00 00 04 02 28 24 00 00 0a 14 7e 33 00 00 0a 7e 33 00 00 0a 16 16 7e 33 00 00 0a 14 12 90 01 01 12 90 01 01 28 16 00 00 06 26 90 00 } //01 00 
		$a_00_1 = {00 00 04 03 28 24 00 00 0a 28 27 00 00 0a 39 } //01 00 
		$a_02_2 = {6f 30 00 00 0a 28 22 00 00 0a 28 23 00 00 0a 11 90 01 01 6f 31 00 00 0a 6f 15 00 00 0a 28 13 00 00 06 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 26 
	condition:
		any of ($a_*)
 
}
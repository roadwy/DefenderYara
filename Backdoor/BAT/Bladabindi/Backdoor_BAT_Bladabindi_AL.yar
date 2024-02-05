
rule Backdoor_BAT_Bladabindi_AL{
	meta:
		description = "Backdoor:BAT/Bladabindi.AL,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 1d 0f 01 1a 28 90 01 01 00 00 06 26 90 00 } //01 00 
		$a_03_1 = {1f 1d 0f 00 1a 28 90 01 01 00 00 06 26 90 00 } //0a 00 
		$a_03_2 = {1f 64 14 13 04 12 04 1f 64 28 90 01 01 00 00 06 90 00 } //0a 00 
		$a_03_3 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 90 01 01 00 00 06 90 00 } //0a 00 
		$a_01_4 = {00 57 52 4b 00 } //00 00 
	condition:
		any of ($a_*)
 
}
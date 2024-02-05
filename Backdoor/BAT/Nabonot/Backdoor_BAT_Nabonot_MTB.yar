
rule Backdoor_BAT_Nabonot_MTB{
	meta:
		description = "Backdoor:BAT/Nabonot!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {28 26 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 90 01 01 11 90 01 01 20 90 01 04 5a 20 90 01 04 61 38 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {20 c4 8e fb 0e 13 90 01 01 11 90 01 01 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 13 90 01 01 11 90 01 01 20 90 01 04 fe 02 13 90 01 01 20 90 01 04 38 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
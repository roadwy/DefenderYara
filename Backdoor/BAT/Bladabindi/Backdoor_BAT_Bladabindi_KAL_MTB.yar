
rule Backdoor_BAT_Bladabindi_KAL_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 04 16 6f 90 01 01 00 00 0a 13 08 12 08 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 04 17 d6 13 04 11 04 11 07 31 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
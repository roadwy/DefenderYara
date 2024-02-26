
rule Backdoor_BAT_Bladabindi_KAK_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 16 9a 7e 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 22 11 21 06 11 22 06 8e 69 11 22 59 6f 90 01 01 00 00 0a 11 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Backdoor_BAT_Bladabindi_KAW_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d b4 03 07 03 8e b7 6a 5d b7 91 61 9c 07 } //00 00 
	condition:
		any of ($a_*)
 
}
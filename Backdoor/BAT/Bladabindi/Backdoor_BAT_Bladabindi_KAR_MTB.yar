
rule Backdoor_BAT_Bladabindi_KAR_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 4a 91 08 08 06 4b 84 95 08 06 1a 58 4b 84 95 d7 6e 20 90 01 01 00 00 00 6a 5f b7 95 61 86 9c 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
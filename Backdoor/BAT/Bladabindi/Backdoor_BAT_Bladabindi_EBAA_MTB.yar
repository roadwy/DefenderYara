
rule Backdoor_BAT_Bladabindi_EBAA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.EBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 83 00 00 04 28 90 01 01 01 00 06 28 90 01 01 01 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 80 90 01 01 00 00 04 20 07 00 00 00 38 90 01 01 fe ff ff 72 b6 02 00 70 80 90 01 01 00 00 04 20 01 00 00 00 fe 0e 00 00 38 90 01 01 fe ff ff 72 b6 02 00 70 80 90 01 01 00 00 04 20 05 00 00 00 fe 0e 00 00 16 39 90 01 01 fe ff ff 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
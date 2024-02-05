
rule Trojan_BAT_AgentTesla_ECN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ECN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 90 01 03 0a 20 9e 02 00 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d b8 90 09 0c 00 08 09 6f 90 01 03 0a 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {69 00 66 00 75 00 5f 00 54 00 } //00 00 
	condition:
		any of ($a_*)
 
}
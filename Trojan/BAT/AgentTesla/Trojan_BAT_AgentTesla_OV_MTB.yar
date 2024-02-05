
rule Trojan_BAT_AgentTesla_OV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 6f 90 02 04 28 90 02 04 28 90 02 04 04 07 6f 90 02 04 28 90 02 04 6a 61 b7 28 90 02 08 28 90 02 09 6f 90 02 04 26 07 04 6f 90 02 04 17 90 00 } //01 00 
		$a_81_1 = {53 75 62 73 74 72 69 6e 67 } //01 00 
		$a_81_2 = {43 6f 6e 63 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
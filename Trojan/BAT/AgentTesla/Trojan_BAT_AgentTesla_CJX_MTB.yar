
rule Trojan_BAT_AgentTesla_CJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 01 02 11 03 18 28 90 01 03 06 1f 10 28 90 01 03 06 84 90 00 } //01 00 
		$a_01_1 = {02 02 8e 69 17 da 91 1f 70 61 13 02 } //01 00 
		$a_01_2 = {11 03 11 06 11 08 11 02 61 11 09 61 b4 9c } //00 00 
	condition:
		any of ($a_*)
 
}
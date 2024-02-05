
rule Trojan_BAT_AgentTesla_DKW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 00 08 18 d6 0c 90 00 } //01 00 
		$a_03_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 0a 9c 09 03 6f 90 01 03 0a 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
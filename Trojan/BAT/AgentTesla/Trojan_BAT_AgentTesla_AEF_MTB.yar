
rule Trojan_BAT_AgentTesla_AEF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 03 0a 9c 90 00 } //01 00 
		$a_03_1 = {06 02 08 23 00 00 00 00 00 00 10 40 28 90 01 03 06 b7 6f 90 01 03 0a 23 00 00 00 00 00 00 70 40 28 90 01 03 0a b7 28 90 01 03 0a 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
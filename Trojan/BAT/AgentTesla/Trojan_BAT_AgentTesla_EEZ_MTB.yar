
rule Trojan_BAT_AgentTesla_EEZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 08 23 00 00 00 00 00 00 10 40 28 90 01 03 0a b7 6f 90 01 03 0a 23 00 00 00 00 00 00 70 40 28 90 01 03 0a b7 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 08 18 d6 0c 90 00 } //01 00 
		$a_03_1 = {08 07 02 07 91 11 04 61 09 06 91 61 28 90 01 03 0a 9c 06 03 6f 90 01 03 0a 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
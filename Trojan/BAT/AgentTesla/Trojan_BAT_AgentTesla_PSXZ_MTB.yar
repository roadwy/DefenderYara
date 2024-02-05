
rule Trojan_BAT_AgentTesla_PSXZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 0c 20 fd 4d a8 22 28 90 01 01 00 00 06 28 90 01 01 00 00 06 20 da 4d a8 22 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 13 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
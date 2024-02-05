
rule Trojan_BAT_AgentTesla_MBFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 4e 00 28 00 35 00 4b 00 28 00 39 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 33 00 28 00 7c 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 7c 00 28 00 7c 00 34 00 } //01 00 
		$a_01_1 = {20 00 4c 00 6f 00 2d 00 61 00 64 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}
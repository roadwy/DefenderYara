
rule Trojan_BAT_AgentTesla_PSXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 3c 45 00 00 28 90 01 01 0a 00 06 28 90 01 01 00 00 0a 20 d4 45 00 00 28 90 01 01 0a 00 06 28 90 01 01 00 00 0a 6f 04 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
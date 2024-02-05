
rule Trojan_BAT_AgentTesla_NZC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 e7 08 00 00 95 e0 95 7e 6c 00 00 04 20 94 0a 00 00 95 61 7e 90 01 01 00 00 04 20 46 09 00 00 95 20 01 01 01 01 13 2e 2e 03 17 2b 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
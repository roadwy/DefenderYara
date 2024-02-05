
rule Trojan_BAT_AgentTesla_NWK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 24 00 00 04 16 9a 20 99 0e 00 00 95 e0 95 7e 24 00 00 04 16 9a 20 6b 08 00 00 95 61 7e 24 00 00 04 16 9a 20 cf 09 00 00 95 2e 09 } //00 00 
	condition:
		any of ($a_*)
 
}
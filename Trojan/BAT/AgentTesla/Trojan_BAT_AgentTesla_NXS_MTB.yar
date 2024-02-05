
rule Trojan_BAT_AgentTesla_NXS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 13 00 00 04 06 7e 13 00 00 04 06 9a 1a 28 42 00 00 0a 72 cf 00 00 70 72 d3 00 00 70 6f 11 00 00 0a a2 06 17 58 0a 06 7e 13 00 00 04 8e 69 32 cf } //01 00 
		$a_01_1 = {7b 0d 00 00 04 06 02 7b 0d 00 00 04 06 9a 1a 28 62 00 00 0a 72 d5 02 00 70 72 d9 02 00 70 6f 1e 00 00 0a a2 06 17 58 0a 06 02 7b 0d 00 00 04 8e 69 32 cc } //00 00 
	condition:
		any of ($a_*)
 
}
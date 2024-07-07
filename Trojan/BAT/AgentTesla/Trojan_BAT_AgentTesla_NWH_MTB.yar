
rule Trojan_BAT_AgentTesla_NWH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 1a 00 00 04 16 9a 20 15 07 00 00 95 e0 95 7e 1a 00 00 04 16 9a 20 a3 05 00 00 95 61 7e 1a 00 00 04 16 9a 20 34 06 00 00 95 2e 03 17 2b 01 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_BAT_AgentTesla_NVO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 04 00 00 04 1a 9a 20 b2 0a 00 00 95 e0 95 7e 04 00 00 04 1a 9a 20 8d 07 00 00 95 61 7e 04 00 00 04 1a 9a 20 57 12 00 00 95 2e 03 17 2b 01 16 58 7e 04 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
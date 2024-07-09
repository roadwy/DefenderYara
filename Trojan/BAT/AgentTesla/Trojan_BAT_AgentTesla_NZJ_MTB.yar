
rule Trojan_BAT_AgentTesla_NZJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 12 06 00 00 95 e0 95 7e ?? 00 00 04 18 9a 20 e7 0f 00 00 95 61 7e 92 00 00 04 18 9a 20 59 12 00 00 95 2e 03 17 2b 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
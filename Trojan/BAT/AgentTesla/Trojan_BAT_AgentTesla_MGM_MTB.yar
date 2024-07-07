
rule Trojan_BAT_AgentTesla_MGM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 06 7b 01 00 00 04 a2 6f 90 01 04 26 2a 90 09 2e 00 73 90 01 04 0a 90 01 14 16 9a 90 01 0a 14 14 17 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
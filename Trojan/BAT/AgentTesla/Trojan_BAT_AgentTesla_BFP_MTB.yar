
rule Trojan_BAT_AgentTesla_BFP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 03 11 04 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 07 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
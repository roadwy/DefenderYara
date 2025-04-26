
rule Trojan_BAT_AgentTesla_MAAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 13 05 11 05 17 58 13 04 11 04 15 2c d3 16 2d f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
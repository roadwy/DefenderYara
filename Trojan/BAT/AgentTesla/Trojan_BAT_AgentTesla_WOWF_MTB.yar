
rule Trojan_BAT_AgentTesla_WOWF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WOWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
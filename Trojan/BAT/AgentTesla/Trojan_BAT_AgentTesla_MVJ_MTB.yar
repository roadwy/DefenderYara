
rule Trojan_BAT_AgentTesla_MVJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 28 11 00 00 0a 28 12 00 00 0a 11 04 6f 13 00 00 0a 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
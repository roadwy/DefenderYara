
rule Trojan_BAT_AgentTesla_PSJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 01 00 00 70 6f 90 01 03 0a 06 28 90 01 03 0a 72 09 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 28 12 00 00 0a 26 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
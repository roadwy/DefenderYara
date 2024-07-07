
rule Trojan_BAT_AgentTesla_RDAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 9f 00 00 0a 28 17 00 00 2b 13 06 11 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
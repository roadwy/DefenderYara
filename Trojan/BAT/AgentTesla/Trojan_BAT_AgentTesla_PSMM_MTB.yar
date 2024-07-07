
rule Trojan_BAT_AgentTesla_PSMM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 73 25 00 00 0a 13 06 00 11 06 72 0a 03 00 70 6f 26 00 00 0a 0a 00 de 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
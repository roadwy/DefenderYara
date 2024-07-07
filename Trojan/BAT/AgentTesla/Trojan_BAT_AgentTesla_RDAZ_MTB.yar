
rule Trojan_BAT_AgentTesla_RDAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 28 34 00 00 0a 0a 02 7b 01 00 00 04 6f 35 00 00 0a 06 16 06 8e 69 6f 36 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
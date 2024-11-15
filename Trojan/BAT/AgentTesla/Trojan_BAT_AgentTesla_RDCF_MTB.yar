
rule Trojan_BAT_AgentTesla_RDCF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 6f 87 00 00 0a 13 08 11 08 02 16 02 8e 69 6f 88 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}

rule Trojan_BAT_AgentTesla_RDBS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 1a 00 00 0a 6f 1c 00 00 0a 02 7b 02 00 00 04 6f 1d 00 00 0a 06 16 06 8e 69 6f 1e 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
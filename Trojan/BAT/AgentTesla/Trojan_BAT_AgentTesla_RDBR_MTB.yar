
rule Trojan_BAT_AgentTesla_RDBR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 6f 8a 00 00 0a 02 16 02 8e 69 6f 8b 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
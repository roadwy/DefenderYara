
rule Trojan_BAT_AgentTesla_PTIC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0f 11 11 6f 44 00 00 0a 00 11 0f 6f 45 00 00 0a 00 11 10 6f 46 00 00 0a 13 12 11 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
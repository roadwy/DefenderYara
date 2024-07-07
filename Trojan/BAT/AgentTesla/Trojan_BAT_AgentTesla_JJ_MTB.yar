
rule Trojan_BAT_AgentTesla_JJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 72 90 01 02 00 70 a2 25 17 72 90 01 02 00 70 a2 14 14 14 7e 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
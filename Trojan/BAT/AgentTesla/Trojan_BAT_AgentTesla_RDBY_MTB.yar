
rule Trojan_BAT_AgentTesla_RDBY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 12 95 d2 13 19 11 10 11 19 61 13 1a 11 07 11 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}

rule Trojan_BAT_AgentTesla_PTEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 11 2d ab 07 28 90 01 01 00 00 0a 13 05 11 05 72 55 10 00 70 6f b7 00 00 0a 13 06 11 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}

rule Trojan_BAT_AgentTesla_ARD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {11 04 06 07 90 01 05 13 05 11 05 90 01 05 13 06 09 08 11 06 b4 9c 07 17 d6 0b 07 16 31 90 01 01 08 17 d6 0c 06 17 d6 0a 06 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
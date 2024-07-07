
rule Trojan_BAT_AgentTesla_ARR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 04 07 14 90 01 05 18 90 01 05 25 16 09 90 01 05 a2 25 17 11 04 90 01 05 a2 25 13 07 14 14 18 90 01 05 25 16 17 9c 25 17 17 9c 25 13 08 90 01 05 13 09 11 08 16 91 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
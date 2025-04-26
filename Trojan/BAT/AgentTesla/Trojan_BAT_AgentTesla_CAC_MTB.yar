
rule Trojan_BAT_AgentTesla_CAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 9a 1f 10 28 ?? 00 00 0a d2 6f ?? 00 00 0a 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d8 } //4
		$a_01_1 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}

rule Trojan_BAT_AgentTesla_MVK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 28 1b 00 00 0a 13 06 } //1
		$a_01_1 = {06 28 14 00 00 0a 74 1e 00 00 01 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}

rule Trojan_BAT_AgentTesla_NCC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 09 11 05 94 58 11 04 11 05 94 58 28 68 00 00 06 28 35 00 00 0a 5d 13 06 09 11 05 94 13 0b 09 11 05 09 11 06 94 9e 09 11 06 11 0b 9e 11 05 17 58 13 05 11 05 28 69 00 00 06 28 35 00 00 0a 32 be } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
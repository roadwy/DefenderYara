
rule Trojan_BAT_AgentTesla_MBAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d d9 } //1
		$a_03_1 = {08 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}

rule Trojan_BAT_AgentTesla_NDL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 29 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 11 05 28 ?? ?? ?? 0a 13 06 17 13 07 07 11 06 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d cc 06 17 58 0a 00 09 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_BAT_AgentTesla_KAAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 09 11 04 6f ?? 00 00 0a 13 05 07 11 05 28 ?? 00 00 0a 08 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 04 17 d6 13 04 11 04 09 6f ?? 00 00 0a fe 04 13 06 11 06 2d c5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
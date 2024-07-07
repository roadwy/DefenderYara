
rule Trojan_BAT_AgentTesla_KAAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 09 11 04 11 07 58 11 06 11 08 58 6f 90 01 01 00 00 0a 13 09 12 09 28 90 01 01 00 00 0a 13 0a 08 07 11 0a 9c 07 17 58 0b 11 08 17 58 13 08 00 11 08 17 fe 04 13 0b 11 0b 2d c9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
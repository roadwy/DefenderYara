
rule Trojan_BAT_AgentTesla_PLLPH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PLLPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 2c 54 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 02 19 8d ?? 00 00 01 25 16 07 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 07 1e 63 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
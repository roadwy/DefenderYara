
rule Trojan_BAT_AgentTesla_YRAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.YRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 2b 29 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 0b 03 6f ?? 00 00 0a 19 58 04 31 cc } //3
		$a_03_1 = {03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 07 17 58 0b } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
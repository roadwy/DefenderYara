
rule Trojan_BAT_AgentTesla_JKIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JKIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 04 1c 58 1c 58 28 ?? ?? ?? 0a 13 1c 03 11 04 1e 58 1e 58 28 ?? ?? ?? 0a 13 0a 03 11 04 1f 14 58 28 ?? ?? ?? 0a 13 1d 11 0a 16 fe 03 13 1e 11 1e 2c 3e 11 0a 8d 10 00 00 01 13 05 03 11 1d 11 05 16 11 05 8e 69 28 ?? ?? ?? 0a 06 7b 23 00 00 04 09 11 1c 58 11 05 11 05 8e 69 12 28 28 ?? ?? ?? 06 16 fe 01 13 1f 11 1f 2c 06 73 82 00 00 0a 7a 11 04 1f 28 58 13 04 11 06 17 58 13 06 11 06 11 11 fe 04 13 20 11 20 3a 72 ff ff ff } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
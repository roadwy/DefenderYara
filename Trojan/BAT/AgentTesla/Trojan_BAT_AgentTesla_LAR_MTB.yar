
rule Trojan_BAT_AgentTesla_LAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2b 08 06 07 6f ?? ?? ?? 0a 26 08 06 07 6f ?? ?? ?? 0a 13 08 11 08 28 ?? ?? ?? 0a 13 09 11 04 09 11 09 28 ?? ?? ?? 0a 9c 07 17 58 0b 07 08 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d c6 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
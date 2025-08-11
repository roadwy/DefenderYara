
rule Trojan_BAT_AgentTesla_ACG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 18 6f ?? 00 00 0a 00 11 05 72 ?? ?? 00 70 12 17 28 ?? 00 00 0a 12 17 28 ?? 00 00 0a 58 12 17 28 ?? 00 00 0a 58 6b 22 00 00 40 40 5b 22 00 00 7f 43 5b 6f } //4
		$a_03_1 = {02 12 07 28 ?? 00 00 0a 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 17 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_ACG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 16 08 a2 25 17 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a2 a2 25 0d 14 14 18 8d ?? ?? ?? ?? 25 16 17 9c 25 13 04 17 } //10
		$a_80_1 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_2 = {46 6f 72 6d 61 74 74 65 72 54 79 70 65 53 74 79 6c 65 } //FormatterTypeStyle  2
		$a_80_3 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}
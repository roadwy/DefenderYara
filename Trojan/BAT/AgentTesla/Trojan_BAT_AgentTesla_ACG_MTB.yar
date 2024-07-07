
rule Trojan_BAT_AgentTesla_ACG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {25 16 08 a2 25 17 19 8d 90 01 04 25 16 7e 90 01 04 a2 25 17 7e 90 01 04 a2 25 18 90 01 0a a2 a2 25 0d 14 14 18 8d 90 01 04 25 16 17 9c 25 13 04 17 90 00 } //10
		$a_80_1 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_2 = {46 6f 72 6d 61 74 74 65 72 54 79 70 65 53 74 79 6c 65 } //FormatterTypeStyle  2
		$a_80_3 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}
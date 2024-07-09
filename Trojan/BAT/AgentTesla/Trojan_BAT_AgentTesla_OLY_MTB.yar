
rule Trojan_BAT_AgentTesla_OLY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_80_0 = {46 6f 72 6d 61 74 74 65 72 54 79 70 65 53 74 79 6c 65 } //FormatterTypeStyle  2
		$a_80_1 = {46 6f 72 4e 65 78 74 43 68 65 63 6b 4f 62 6a } //ForNextCheckObj  2
		$a_80_2 = {46 6f 72 4c 6f 6f 70 49 6e 69 74 4f 62 6a } //ForLoopInitObj  2
		$a_80_3 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_4 = {45 71 75 61 6c 69 74 79 43 6f 6d 70 61 72 65 72 } //EqualityComparer  2
		$a_80_5 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_6 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_7 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  2
		$a_02_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 [0-25] 2e 00 78 00 73 00 64 00 } //2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_02_8  & 1)*2) >=18
 
}

rule Trojan_BAT_AgentTesla_OLQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_02_0 = {9a 13 05 11 05 28 90 01 04 23 00 00 00 00 00 80 73 40 59 28 90 01 04 b7 13 06 07 11 06 28 90 01 04 6f 90 01 04 26 11 04 17 d6 13 04 00 11 04 09 8e 69 fe 04 16 fe 01 90 00 } //10
		$a_80_1 = {46 6f 72 6d 61 74 74 65 72 54 79 70 65 53 74 79 6c 65 } //FormatterTypeStyle  2
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_3 = {45 71 75 61 6c 69 74 79 43 6f 6d 70 61 72 65 72 } //EqualityComparer  2
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}
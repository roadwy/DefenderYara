
rule Trojan_BAT_AgentTesla_MF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 1d 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 31 00 00 00 09 00 00 00 2b 00 00 00 38 00 00 00 1d } //1
		$a_03_1 = {0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 dd 2d 01 00 00 20 00 00 af 0d fe 0e 06 00 00 fe 0d 06 00 48 68 d3 13 05 2b 0a 90 00 } //1
		$a_01_2 = {61 70 69 6d 69 74 } //1 apimit
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_MF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0b 2b f3 72 90 01 01 00 00 70 28 90 01 03 0a 13 07 11 07 14 fe 03 13 08 11 08 2c 57 11 07 6f 90 01 03 0a 0a 06 14 fe 03 13 09 11 09 2c 45 06 6f 90 01 03 0a 0b 73 90 01 01 00 00 0a 0c 20 00 04 00 00 8d 03 00 00 01 13 04 07 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 08 11 04 16 11 05 6f 90 01 03 0a 11 06 11 05 58 13 06 11 05 16 fe 02 13 0a 11 0a 2d d4 90 00 } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {45 78 63 65 70 74 69 6f 6e } //1 Exception
		$a_01_7 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
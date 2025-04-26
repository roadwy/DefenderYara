
rule Trojan_BAT_AgentTesla_RPQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 04 09 6f af 00 00 0a 6f a4 00 00 06 0c 02 04 09 6f af 00 00 0a 6f 9b 00 00 06 07 5a 07 18 5b 58 6c 05 09 9a 6f ce 00 00 0a 23 00 00 00 00 00 00 00 40 5b 59 04 09 6f af 00 00 0a 6f 9d 00 00 06 07 5a 07 18 5b 58 6c 05 09 9a 6f cf 00 00 0a 23 00 00 00 00 00 00 00 40 5b 59 08 06 05 09 9a 28 76 00 00 06 00 00 09 17 58 0d 09 04 6f b0 00 00 0a fe 04 13 04 11 04 2d 86 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 00 72 00 6d 00 61 00 76 00 69 00 70 00 67 00 65 00 6e 00 65 00 73 00 68 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 6b 00 69 00 64 00 6f 00 2f 00 6d 00 79 00 64 00 6c 00 6c 00 2e 00 74 00 78 00 74 00 } //1 armavipgenesh.com/skido/mydll.txt
		$a_01_1 = {52 00 55 00 4e 00 52 00 55 00 4e 00 52 00 55 00 4e 00 } //1 RUNRUNRUN
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {42 69 6e 64 65 72 } //1 Binder
		$a_01_7 = {43 6f 6e 76 65 72 74 } //1 Convert
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_RPQ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 06 00 28 ?? ?? 00 0a 28 ?? ?? 00 0a fe 0c 03 00 fe 0c 06 00 6f ?? ?? 00 0a 67 52 fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00 fe 0c 06 00 fe 0c 03 00 6f ?? ?? 00 0a 3f bf ff ff ff } //1
		$a_01_1 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 6f 6e 76 65 72 74 46 72 6f 6d 55 74 66 33 32 } //1 ConvertFromUtf32
		$a_01_4 = {54 6f 43 68 61 72 } //1 ToChar
		$a_01_5 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_01_6 = {4c 65 6e 67 74 68 } //1 Length
		$a_01_7 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_RPQ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 00 6d 00 61 00 7a 00 6f 00 6e 00 61 00 77 00 73 00 2e 00 63 00 6f 00 6d } //1
		$a_01_1 = {4b 00 65 00 66 00 70 00 61 00 62 00 7a 00 2e 00 70 00 6e 00 67 } //1
		$a_01_2 = {52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 } //1
		$a_01_3 = {53 00 6c 00 65 00 65 00 70 } //1
		$a_01_4 = {45 00 63 00 67 00 78 00 6e 00 62 } //1
		$a_01_5 = {47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
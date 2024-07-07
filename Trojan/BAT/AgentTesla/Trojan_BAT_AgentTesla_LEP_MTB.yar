
rule Trojan_BAT_AgentTesla_LEP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_1 = {23 64 66 67 66 67 23 } //1 #dfgfg#
		$a_01_2 = {23 67 64 66 67 64 66 67 23 } //1 #gdfgdfg#
		$a_01_3 = {23 73 73 73 73 73 73 73 73 73 2e 64 6c 6c 23 } //1 #sssssssss.dll#
		$a_01_4 = {23 66 73 68 67 68 68 68 67 66 67 67 67 67 68 64 66 73 64 66 2e 64 6c 6c 23 } //1 #fshghhhgfgggghdfsdf.dll#
		$a_01_5 = {23 66 73 64 66 67 64 64 64 64 64 66 63 68 61 66 68 67 68 67 73 64 66 2e 64 6c 6c 23 } //1 #fsdfgdddddfchafhghgsdf.dll#
		$a_01_6 = {00 66 73 68 64 64 64 64 64 64 64 64 64 67 68 64 00 } //1
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}

rule Trojan_BAT_AgentTesla_JBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_00_0 = {06 02 07 6f 1e 00 00 0a 03 07 03 6f 19 00 00 0a 5d 6f 1e 00 00 0a 61 d1 6f 1f 00 00 0a 26 07 17 58 0b 07 02 6f } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}
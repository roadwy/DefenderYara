
rule Trojan_BAT_AgentTesla_LPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 68 64 66 73 61 66 61 61 61 61 64 61 64 73 61 64 66 66 66 77 74 77 66 66 66 66 66 66 66 67 73 73 73 73 73 64 66 2e 64 6c 6c 23 } //1 #hdfsafaaaadadsadfffwtwfffffffgsssssdf.dll#
		$a_01_1 = {23 64 64 73 68 73 73 74 61 64 61 61 61 64 77 73 73 73 73 73 67 2e 64 6c 6c 23 } //1 #ddshsstadaaadwsssssg.dll#
		$a_01_2 = {23 61 67 66 66 61 2e 64 6c 6c 23 } //1 #agffa.dll#
		$a_01_3 = {23 66 2e 64 67 64 64 64 6c 6c 23 } //1 #f.dgdddll#
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
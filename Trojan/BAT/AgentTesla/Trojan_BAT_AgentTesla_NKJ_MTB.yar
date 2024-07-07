
rule Trojan_BAT_AgentTesla_NKJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {23 66 66 67 66 67 66 61 2e 64 6c 6c 23 } //1 #ffgfgfa.dll#
		$a_01_1 = {23 66 61 67 64 66 67 66 64 23 } //1 #fagdfgfd#
		$a_01_2 = {6b 67 64 66 67 64 66 66 23 } //1 kgdfgdff#
		$a_01_3 = {23 67 64 68 66 64 73 67 73 64 67 2e 64 6c 6c 23 } //1 #gdhfdsgsdg.dll#
		$a_01_4 = {23 73 61 64 61 61 61 61 67 66 64 67 61 64 61 61 61 64 76 63 78 76 61 64 61 61 64 66 67 64 73 2e 64 6c 6c 23 } //1 #sadaaaagfdgadaaadvcxvadaadfgds.dll#
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
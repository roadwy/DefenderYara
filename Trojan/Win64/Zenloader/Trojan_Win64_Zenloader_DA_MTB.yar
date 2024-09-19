
rule Trojan_Win64_Zenloader_DA_MTB{
	meta:
		description = "Trojan:Win64/Zenloader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 62 73 6f 6c 75 74 65 43 6c 69 65 6e 74 4d 61 69 6e } //20 AbsoluteClientMain
		$a_01_1 = {72 75 6e 6d 6f 64 75 6c 65 } //1 runmodule
		$a_01_2 = {23 35 30 30 32 23 } //1 #5002#
		$a_01_3 = {23 35 30 30 34 23 } //1 #5004#
		$a_01_4 = {23 35 30 30 36 23 } //1 #5006#
		$a_01_5 = {23 35 30 30 38 23 } //1 #5008#
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=25
 
}
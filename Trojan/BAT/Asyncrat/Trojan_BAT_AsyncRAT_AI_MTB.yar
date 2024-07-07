
rule Trojan_BAT_AsyncRAT_AI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 14 14 6f 90 01 01 00 00 0a 26 2a 90 00 } //2
		$a_01_1 = {08 09 8e b7 32 } //2
		$a_01_2 = {08 17 d6 0c } //2
		$a_01_3 = {08 9a 0b 06 07 18 28 } //2
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}
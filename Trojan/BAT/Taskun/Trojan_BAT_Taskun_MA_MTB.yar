
rule Trojan_BAT_Taskun_MA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {78 57 5a 6a 71 6e 41 63 43 33 42 41 39 6a 78 51 4c 72 } //1 xWZjqnAcC3BA9jxQLr
		$a_01_1 = {69 4a 5a 69 6b 56 44 54 78 43 } //1 iJZikVDTxC
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {52 00 6f 00 63 00 6b 00 20 00 63 00 72 00 75 00 73 00 68 00 65 00 73 00 20 00 4c 00 69 00 7a 00 61 00 72 00 64 00 } //1 Rock crushes Lizard
		$a_01_5 = {53 68 6f 55 32 41 66 36 63 } //1 ShoU2Af6c
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
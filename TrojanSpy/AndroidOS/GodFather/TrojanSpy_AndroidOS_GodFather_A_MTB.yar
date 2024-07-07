
rule TrojanSpy_AndroidOS_GodFather_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GodFather.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 61 6c 6c 46 6f 72 77 61 72 64 } //1 callForward
		$a_00_1 = {53 65 6e 64 4e 65 77 55 73 65 72 } //1 SendNewUser
		$a_00_2 = {53 65 6e 64 4b 65 79 6c 6f 67 } //1 SendKeylog
		$a_00_3 = {6c 69 6e 6b 6f 70 65 6e } //1 linkopen
		$a_00_4 = {69 73 45 6d 75 6c 61 74 6f 72 } //1 isEmulator
		$a_00_5 = {53 65 6e 64 55 53 44 } //1 SendUSD
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
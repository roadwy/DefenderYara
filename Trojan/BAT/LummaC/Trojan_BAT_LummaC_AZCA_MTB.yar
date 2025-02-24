
rule Trojan_BAT_LummaC_AZCA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AZCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 65 76 65 6c 6f 70 20 6d 6f 6f 6e 20 69 6e 73 70 69 72 65 20 65 6e 65 72 67 79 20 69 74 20 6e 65 74 77 6f 72 6b 20 62 61 6e 61 6e 61 20 64 65 76 65 6c 6f 70 20 62 6c 61 63 6b 20 73 6f 6c 75 74 69 6f 6e } //2 develop moon inspire energy it network banana develop black solution
		$a_01_1 = {77 68 69 74 65 20 69 6d 70 72 6f 76 65 20 73 75 70 70 6f 72 74 20 6f 62 6a 65 63 74 20 64 61 72 6b } //2 white improve support object dark
		$a_01_2 = {69 6e 74 65 67 72 61 74 65 20 75 6e 64 65 72 73 74 61 6e 64 20 73 68 65 } //2 integrate understand she
		$a_01_3 = {70 6f 77 65 72 20 63 6f 6d 70 6c 65 78 20 62 6c 75 65 } //1 power complex blue
		$a_01_4 = {24 30 64 36 66 63 39 65 36 2d 64 38 65 39 2d 34 30 36 65 2d 38 38 63 33 2d 36 37 63 65 38 36 62 33 38 64 65 35 } //1 $0d6fc9e6-d8e9-406e-88c3-67ce86b38de5
		$a_01_5 = {74 68 65 79 20 63 6f 6d 70 6c 65 78 20 73 68 65 } //1 they complex she
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}
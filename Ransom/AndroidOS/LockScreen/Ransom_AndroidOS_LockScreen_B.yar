
rule Ransom_AndroidOS_LockScreen_B{
	meta:
		description = "Ransom:AndroidOS/LockScreen.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 6b 70 68 6f 6e 65 2f 6b 69 6c 6c 73 65 72 76 65 24 } //1 lockphone/killserve$
		$a_01_1 = {76 61 6c 24 6b 69 6c 6c 00 } //1
		$a_01_2 = {70 61 73 73 77 6f 72 64 5f 6f 6e 00 } //1 慰獳潷摲潟n
		$a_01_3 = {6b 69 6c 6c 73 65 72 76 65 2e 6a 61 76 61 00 } //1
		$a_01_4 = {4e 65 72 6f 2e 6c 6f 63 6b 70 68 6f 6e 65 2e 4d 61 69 6e 41 63 74 69 76 69 74 79 00 } //1 敎潲氮捯火潨敮䴮楡䅮瑣癩瑩y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
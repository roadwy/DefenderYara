
rule Trojan_AndroidOS_Spynote_F{
	meta:
		description = "Trojan:AndroidOS/Spynote.F,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 73 70 79 6d 61 78 2f 73 74 75 62 37 2f 43 6c 61 73 73 47 65 6e 31 32 } //1 Lspymax/stub7/ClassGen12
		$a_01_1 = {63 61 6e 47 6f 42 61 63 6b } //1 canGoBack
		$a_00_2 = {73 70 79 6d 61 78 2e 73 74 75 62 37 2e 73 75 66 66 69 78 } //1 spymax.stub7.suffix
		$a_01_3 = {2f 43 6c 61 73 73 47 65 6e 33 } //1 /ClassGen3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
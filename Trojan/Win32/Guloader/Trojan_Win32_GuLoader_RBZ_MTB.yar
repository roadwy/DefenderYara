
rule Trojan_Win32_GuLoader_RBZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 61 72 69 7a 6f 6e 69 61 6e 73 5c 74 6f 6c 6c 6f } //1 \arizonians\tollo
		$a_81_1 = {69 6e 64 73 20 61 6e 74 69 70 72 6f 64 75 63 74 69 76 65 20 70 61 6e 74 6f 6d 65 74 72 69 63 61 6c } //1 inds antiproductive pantometrical
		$a_81_2 = {69 6e 74 65 6c 6c 69 67 65 6e 63 65 72 20 70 72 61 6b 74 69 6b 61 62 6c 65 } //1 intelligencer praktikable
		$a_81_3 = {74 72 6f 63 68 61 69 63 61 6c 69 74 79 20 61 63 68 72 6f 6d 6f 74 72 69 63 68 69 61 20 75 6e 6f 6d 6e 69 70 6f 74 65 6e 74 6c 79 } //1 trochaicality achromotrichia unomnipotently
		$a_81_4 = {62 61 72 6d 68 6a 65 72 74 69 67 74 } //1 barmhjertigt
		$a_81_5 = {61 6e 74 69 63 69 70 65 72 65 74 20 73 6b 72 76 65 62 65 6c 67 6e 69 6e 67 65 6e 73 } //1 anticiperet skrvebelgningens
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
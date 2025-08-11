
rule Trojan_Win32_GuLoader_SUE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 7a 61 72 69 6e 61 73 5c 61 61 72 65 66 6f 72 66 65 64 74 6e 69 6e 67 65 6e 73 } //1 \zarinas\aareforfedtningens
		$a_81_1 = {5c 43 68 61 70 65 6c 72 79 37 36 2e 62 6d 70 } //1 \Chapelry76.bmp
		$a_81_2 = {44 65 6b 6c 61 6d 61 74 6f 72 65 6e 73 2e 74 72 6f } //1 Deklamatorens.tro
		$a_81_3 = {53 75 74 74 65 6b 6c 75 64 65 6e 65 2e 72 65 6c } //1 Suttekludene.rel
		$a_81_4 = {64 75 6d 72 69 61 6e 73 2e 74 61 66 } //1 dumrians.taf
		$a_81_5 = {70 72 65 70 65 6e 64 2e 6b 6f 6e } //1 prepend.kon
		$a_81_6 = {5c 65 71 75 69 6f 6d 6e 69 70 6f 74 65 6e 74 5c 76 61 6e 67 65 72 73 2e 74 78 74 } //1 \equiomnipotent\vangers.txt
		$a_81_7 = {72 69 64 69 63 75 6c 69 73 65 5c 74 6f 73 73 65 68 6f 76 65 64 65 72 6e 65 73 5c } //1 ridiculise\tossehovedernes\
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}

rule Trojan_BAT_AveMaria_NEED_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 38 36 33 37 31 37 65 2d 39 36 31 61 2d 34 39 38 62 2d 38 33 39 39 2d 62 30 36 61 32 38 37 36 62 30 34 33 } //5 c863717e-961a-498b-8399-b06a2876b043
		$a_01_1 = {54 61 67 73 4f 66 53 65 6e 74 65 6e 63 65 } //2 TagsOfSentence
		$a_01_2 = {47 72 61 6d 6d 65 72 73 4f 66 53 65 6e 74 65 6e 63 65 } //2 GrammersOfSentence
		$a_01_3 = {47 72 61 6d 6d 65 72 73 50 6f 73 73 69 62 6c 65 } //2 GrammersPossible
		$a_01_4 = {41 6c 6c 61 64 69 6e 20 52 65 61 6c 74 79 20 32 30 32 33 } //2 Alladin Realty 2023
		$a_01_5 = {44 61 74 61 62 61 73 65 31 2e 73 64 66 } //2 Database1.sdf
		$a_01_6 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //2 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=17
 
}
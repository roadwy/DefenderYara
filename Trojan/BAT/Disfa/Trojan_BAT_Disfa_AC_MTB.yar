
rule Trojan_BAT_Disfa_AC_MTB{
	meta:
		description = "Trojan:BAT/Disfa.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 0f 00 05 00 00 "
		
	strings :
		$a_02_0 = {11 05 11 04 6f 90 01 03 0a 0d 06 09 28 90 01 03 0a 90 01 01 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 11 04 17 d6 13 04 11 04 11 06 32 d1 06 28 90 01 03 0a 0a 06 2a 90 00 } //10
		$a_80_1 = {50 72 30 74 33 5f 44 65 63 72 79 70 54 } //Pr0t3_DecrypT  5
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  4
		$a_80_3 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  3
		$a_80_4 = {72 61 77 41 73 73 65 6d 62 6c 79 } //rawAssembly  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=15
 
}
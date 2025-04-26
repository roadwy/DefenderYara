
rule Trojan_BAT_njRAT_MBAU_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {c5 c6 b4 c6 f2 5d 28 c7 44 c5 44 c5 4c c7 44 c5 44 c5 44 c5 44 c5 59 c5 44 c5 44 c5 44 c5 44 c5 2f 00 2f 00 38 00 44 c5 44 c5 4d c7 e8 } //3
		$a_01_1 = {d4 c6 0b 4e e8 5d 28 c7 44 c5 44 c5 44 c5 d4 c6 ba 4e 4c c5 e8 5d 44 c5 44 c5 48 c5 e5 5d e3 53 44 c5 } //3
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
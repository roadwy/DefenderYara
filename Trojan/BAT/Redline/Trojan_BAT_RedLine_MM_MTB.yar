
rule Trojan_BAT_RedLine_MM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 2b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6e 00 00 00 77 } //10
		$a_01_1 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {49 73 4c 69 74 74 6c 65 45 6e 64 69 61 6e } //1 IsLittleEndian
		$a_01_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}
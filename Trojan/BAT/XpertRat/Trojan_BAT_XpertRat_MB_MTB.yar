
rule Trojan_BAT_XpertRat_MB_MTB{
	meta:
		description = "Trojan:BAT/XpertRat.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 25 72 0b 00 00 70 6f ?? ?? ?? 0a 25 72 21 00 00 70 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_3 = {51 75 65 72 79 52 65 71 75 65 73 74 } //1 QueryRequest
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {43 68 65 63 6b 52 65 71 75 65 73 74 } //1 CheckRequest
		$a_81_6 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //1 get_FullName
		$a_81_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}

rule Trojan_BAT_FormBook_NZT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 0f 00 28 90 01 01 00 00 06 25 26 0f 01 28 90 01 01 00 00 06 90 02 10 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a 90 00 } //1
		$a_01_1 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
		$a_81_2 = {4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 } //1 MTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTg
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
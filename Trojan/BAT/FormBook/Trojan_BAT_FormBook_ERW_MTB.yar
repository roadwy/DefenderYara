
rule Trojan_BAT_FormBook_ERW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ERW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {35 00 47 00 5a 00 47 00 34 00 42 00 54 00 50 00 48 00 5a 00 41 00 42 00 43 00 47 00 37 00 35 00 35 00 4f 00 56 00 51 00 5a 00 54 00 } //10 5GZG4BTPHZABCG755OVQZT
		$a_01_1 = {41 00 74 00 68 00 6c 00 65 00 74 00 65 00 } //5 Athlete
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}
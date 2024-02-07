
rule Trojan_BAT_FormBook_CWC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 00 2d 53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 } //01 00 
		$a_01_1 = {00 45 6e 63 6f 64 65 72 73 00 } //01 00  䔀据摯牥s
		$a_01_2 = {00 44 65 63 6f 64 65 72 00 } //01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_5 = {43 6f 6e 76 65 72 74 6f 72 } //01 00  Convertor
		$a_01_6 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}
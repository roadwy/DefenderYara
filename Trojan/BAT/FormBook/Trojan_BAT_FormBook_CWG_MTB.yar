
rule Trojan_BAT_FormBook_CWG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 44 6f 49 74 00 54 72 79 46 6f 72 49 74 00 } //01 00 
		$a_01_1 = {00 45 6e 63 6f 64 65 72 73 00 63 75 73 74 6f 6d 65 72 73 00 } //01 00  䔀据摯牥s畣瑳浯牥s
		$a_03_2 = {48 65 6c 70 65 72 90 01 0e 43 6f 6e 76 65 72 74 6f 72 90 00 } //01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}
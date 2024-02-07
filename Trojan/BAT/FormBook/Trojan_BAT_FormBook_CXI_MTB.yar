
rule Trojan_BAT_FormBook_CXI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 73 00 74 00 2d 00 4e 00 65 00 74 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00  Test-NetConnection
		$a_01_1 = {00 45 6e 63 6f 64 65 72 00 67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_4 = {00 43 6f 6e 76 65 72 74 6f 72 00 } //01 00 
		$a_01_5 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_8 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_9 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //00 00  GetExportedTypes
	condition:
		any of ($a_*)
 
}
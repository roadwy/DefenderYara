
rule Trojan_BAT_FormBook_EYF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 38 00 44 00 32 00 35 00 54 00 } //01 00  B8D25T
		$a_01_1 = {50 00 61 00 72 00 65 00 74 00 68 00 65 00 72 00 66 00 6c 00 65 00 6e 00 2e 00 54 00 75 00 63 00 73 00 6f 00 6e 00 } //01 00  Paretherflen.Tucson
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}
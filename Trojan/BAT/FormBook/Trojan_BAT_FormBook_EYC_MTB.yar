
rule Trojan_BAT_FormBook_EYC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 50 43 44 41 43 38 34 45 37 44 35 39 39 46 47 59 38 47 37 4b 44 } //01 00  FPCDAC84E7D599FGY8G7KD
		$a_01_1 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}
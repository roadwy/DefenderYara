
rule Trojan_BAT_DCRat_PSFJ_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PSFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 3c 00 00 0a 26 73 90 01 03 0a 13 0b 73 90 01 03 0a 13 0c 28 90 01 03 0a 11 06 6f 90 01 03 0a 13 0d 11 0c 11 0d 16 11 0d 8e 69 73 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 11 0b 72 90 01 03 70 72 90 01 03 70 28 90 01 03 06 72 90 01 03 70 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 11 0c 6f 90 01 03 0a 6f 90 01 03 0a 11 0b 6f 90 01 03 0a de 0c 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //01 00  NewLateBinding
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_4 = {48 74 74 70 4d 65 73 73 61 67 65 49 6e 76 6f 6b 65 72 } //01 00  HttpMessageInvoker
		$a_01_5 = {47 65 74 4e 65 74 77 6f 72 6b 49 6e 66 6f } //00 00  GetNetworkInfo
	condition:
		any of ($a_*)
 
}
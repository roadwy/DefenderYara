
rule Trojan_BAT_Fareit_MB_MTB{
	meta:
		description = "Trojan:BAT/Fareit.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0b 07 1f 20 8d 0d 00 00 01 25 d0 90 01 03 04 28 90 01 03 0a 6f 90 01 03 0a 07 1f 10 8d 0d 00 00 01 25 d0 90 01 03 04 28 90 01 03 0a 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 03 0a 08 6f 90 01 03 0a 06 28 90 01 03 06 0d 28 90 01 03 06 09 2a 90 00 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_RedLineStealer_MDA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 6f 89 00 00 0a 17 73 90 01 01 00 00 0a 25 02 16 02 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 06 28 90 01 03 06 28 90 01 03 06 2a 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //01 00  base64EncodedData
		$a_01_8 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}
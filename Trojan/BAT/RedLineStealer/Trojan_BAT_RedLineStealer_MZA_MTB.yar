
rule Trojan_BAT_RedLineStealer_MZA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 2d 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 0c 06 72 90 01 03 70 08 28 90 01 03 0a 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 32 ca 06 6f 90 01 03 0a 2a 90 00 } //1
		$a_01_1 = {42 79 74 65 73 54 6f 53 74 72 69 6e 67 43 6f 6e 76 65 72 74 65 64 } //1 BytesToStringConverted
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 EncryptedData
		$a_01_5 = {44 65 63 72 79 70 74 42 6c 6f 62 } //1 DecryptBlob
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_8 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_9 = {62 72 6f 77 73 65 72 50 61 74 68 73 } //1 browserPaths
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
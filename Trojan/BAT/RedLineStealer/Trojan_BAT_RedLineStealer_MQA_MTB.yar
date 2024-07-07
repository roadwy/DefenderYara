
rule Trojan_BAT_RedLineStealer_MQA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 90 01 01 00 00 0a 73 90 01 01 00 00 06 13 0d 16 13 16 38 23 00 00 00 11 0d 6f 90 01 03 06 13 17 11 0d 6f 90 01 03 06 13 18 11 04 11 17 11 18 6f 90 01 03 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff 11 0d 6f 90 01 03 06 11 04 80 90 01 01 00 00 04 dd 90 00 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 42 6c 6f 63 6b } //1 TransformBlock
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_7 = {62 61 73 65 36 34 45 6e 63 6f 64 65 64 44 61 74 61 } //1 base64EncodedData
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
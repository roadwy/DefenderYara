
rule Trojan_BAT_RedLineStealer_ME_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {13 0d 17 11 0d 11 0c 28 ?? ?? ?? 06 13 0e 11 0e 02 1a 02 8e 69 1a 59 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 de } //1
		$a_03_1 = {13 0d 11 0d 28 ?? ?? ?? 0a 26 11 0d 07 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 0e 11 0e 28 ?? ?? ?? 0a 2d 2d 11 0e 28 ?? ?? ?? 0a 25 11 0b 16 11 0b 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0e 14 1a } //1
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_10 = {53 00 65 00 63 00 75 00 72 00 65 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 53 00 68 00 65 00 6c 00 6c 00 } //1 Secure System Shell
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
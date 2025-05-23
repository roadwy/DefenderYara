
rule Trojan_BAT_RedLineStealer_MAA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_03_0 = {0a 13 0d 20 04 00 00 00 28 ?? ?? ?? 06 3a cb ff ff ff 26 20 02 00 00 00 38 c0 ff ff ff 00 00 11 0d 11 07 28 0c 00 00 06 17 73 0b 00 00 0a 13 04 20 00 00 00 00 28 ?? ?? ?? 06 39 0a 00 00 00 26 38 00 00 00 00 fe 0c 0a 00 45 03 00 00 00 19 00 00 00 05 00 00 00 13 01 00 00 38 14 00 00 00 00 11 0d 28 ?? ?? ?? 06 13 0b 20 02 00 00 00 38 d6 ff ff ff 00 00 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 20 01 00 00 00 28 ?? ?? ?? 06 3a 0f 00 00 00 26 20 01 00 00 00 38 } //1
		$a_00_1 = {26 38 ca fd ff ff 00 11 07 11 01 11 07 6f 0d 00 00 0a 1e 5b 28 09 00 00 06 } //1
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_5 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //1 set_KeySize
		$a_81_6 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //1 get_KeySize
		$a_81_7 = {67 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 } //1 get_BlockSize
		$a_81_8 = {43 72 79 70 74 65 64 } //1 Crypted
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {73 65 74 5f 49 56 } //1 set_IV
		$a_81_11 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}
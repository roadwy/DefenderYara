
rule Trojan_BAT_RedLineStealer_MAG_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 1f 0f 59 8d ?? 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? 0a 1f 10 8d ?? 00 00 01 0c 07 8e 69 08 8e 69 59 8d ?? 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 ?? ?? ?? 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? 0a 73 ?? 00 00 06 03 06 14 09 08 6f ?? ?? ?? 06 13 04 de } //1
		$a_81_1 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {67 65 74 5f 55 73 65 72 44 6f 6d 61 69 6e 4e 61 6d 65 } //1 get_UserDomainName
		$a_81_6 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_9 = {54 72 79 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e } //1 TryGetConnection
		$a_81_10 = {67 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //1 get_Credentials
		$a_81_11 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}
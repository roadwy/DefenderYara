
rule Trojan_BAT_RedLineStealer_MS_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 16 0b 2b 26 06 02 07 6f ?? ?? ?? 0a 03 07 03 6f 84 00 00 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d1 06 6f ?? ?? ?? 0a 2a } //1
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_4 = {67 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //1 get_Credentials
		$a_81_5 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //1 StringDecrypt
		$a_81_6 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_7 = {53 6c 65 65 70 } //1 Sleep
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_9 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_11 = {44 65 63 72 79 70 74 42 6c 6f 62 } //1 DecryptBlob
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}
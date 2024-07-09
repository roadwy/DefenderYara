
rule Trojan_BAT_RedLineStealer_ABI_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_03_0 = {06 02 6f 97 ?? ?? 0a 0b 28 98 ?? ?? 0a 72 43 ?? ?? 70 28 46 ?? ?? 0a 0c 08 07 28 99 ?? ?? 0a 00 08 28 5c ?? ?? 0a 26 00 de 14 } //3
		$a_03_1 = {0a 02 7b 82 ?? ?? 04 02 7b 83 ?? ?? 04 17 6f 91 ?? ?? 0a 00 28 08 ?? ?? 06 6f 92 ?? ?? 0a 72 e8 ?? ?? 70 72 68 ?? ?? 70 02 7b 83 ?? ?? 04 72 9a ?? ?? 70 28 46 ?? ?? 0a 6f 93 ?? ?? 0a 00 de 0f } //3
		$a_01_2 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_3 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_01_4 = {43 68 72 6f 6d 65 43 6f 6f 6b 69 65 50 61 74 68 } //1 ChromeCookiePath
		$a_01_5 = {77 61 6c 6c 65 74 5f 6c 6f 67 } //1 wallet_log
		$a_01_6 = {47 65 74 41 70 70 44 61 74 61 50 61 74 68 } //1 GetAppDataPath
		$a_01_7 = {47 65 74 4f 75 74 6c 6f 6f 6b 50 61 73 73 77 6f 72 64 73 } //1 GetOutlookPasswords
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_00_9 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1) >=14
 
}
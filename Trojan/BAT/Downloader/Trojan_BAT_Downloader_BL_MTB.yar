
rule Trojan_BAT_Downloader_BL_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 25 19 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 20 ?? ?? ?? ?? 6f ?? ?? ?? 0a 25 20 ?? ?? ?? ?? 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 28 } //1
		$a_03_1 = {0b 06 07 6f ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 25 8e 69 8d ?? ?? ?? 01 0d 73 ?? ?? ?? 0a 08 16 73 ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //1 DecryptString
		$a_01_4 = {45 6e 63 72 79 70 74 53 74 72 69 6e 67 } //1 EncryptString
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
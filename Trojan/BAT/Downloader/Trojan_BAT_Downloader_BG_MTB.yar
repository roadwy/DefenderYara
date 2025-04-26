
rule Trojan_BAT_Downloader_BG_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 74 68 65 64 65 76 69 6c 63 6f 64 65 72 2e 65 78 65 } //1 C:\Windows\Microsoft.NET\Framework\v4.0.30319\thedevilcoder.exe
		$a_81_1 = {52 55 4e 4e 4e 4e } //1 RUNNNN
		$a_81_2 = {74 68 65 64 65 76 69 6c 63 6f 64 65 72 } //1 thedevilcoder
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {4e 65 74 77 6f 72 6b 43 68 61 6e 67 65 } //1 NetworkChange
		$a_01_5 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_6 = {46 69 65 6c 64 42 75 69 6c 64 65 72 } //1 FieldBuilder
		$a_01_7 = {38 6c dc 8f 0d 4e 81 89 40 67 7b 6b 00 4e 2a 4e 09 67 c1 54 73 54 84 76 ba 4e 63 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
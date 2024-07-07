
rule TrojanDownloader_Win32_Zlob_gen_CB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {c6 85 ec fe ff ff 47 c6 85 ed fe ff ff 45 c6 85 ee fe ff ff 54 88 9d ef fe ff ff ff 55 } //6
		$a_03_1 = {fe ff ff 47 c6 85 90 01 01 fe ff ff 45 c6 85 90 01 01 fe ff ff 54 88 9d 90 01 01 fe ff ff ff 55 90 00 } //4
		$a_01_2 = {00 5f 52 45 44 44 5f 00 } //1 开䕒䑄_
		$a_01_3 = {00 73 74 65 72 65 6f 00 } //1 猀整敲o
		$a_01_4 = {53 65 61 72 63 68 53 63 6f 70 65 73 } //1 SearchScopes
		$a_01_5 = {00 76 65 2e 00 6c 69 00 } //1
		$a_01_6 = {00 6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00 } //1
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
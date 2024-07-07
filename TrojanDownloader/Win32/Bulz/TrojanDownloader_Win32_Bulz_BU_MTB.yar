
rule TrojanDownloader_Win32_Bulz_BU_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bulz.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 04 8d 44 24 10 50 6a 06 56 ff 15 } //1
		$a_01_1 = {6a 00 6a 00 6a 03 6a 00 6a 00 ff b5 c8 fb ff ff 50 57 ff 15 } //1
		$a_01_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 68 00 34 00 38 00 79 00 6f 00 72 00 62 00 71 00 36 00 72 00 6d 00 38 00 37 00 7a 00 6f 00 74 00 } //1 Global\h48yorbq6rm87zot
		$a_01_3 = {61 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //1 app.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
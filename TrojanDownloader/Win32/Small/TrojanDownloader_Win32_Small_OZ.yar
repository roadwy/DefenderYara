
rule TrojanDownloader_Win32_Small_OZ{
	meta:
		description = "TrojanDownloader:Win32/Small.OZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 6f 2e 73 69 6e 61 62 63 2e 6e 65 74 2f 61 62 63 2e 65 78 65 00 00 00 } //1
		$a_01_1 = {7e 2e 65 78 65 00 00 00 55 } //1
		$a_01_2 = {65 66 32 36 65 76 2e 64 6c 6c 00 00 ff } //1
		$a_01_3 = {61 62 63 2e 65 78 65 20 31 39 37 39 30 32 30 35 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule TrojanDownloader_Win32_Banload_ZX{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 55 f8 89 45 fc b8 90 01 04 e8 90 01 03 ff 68 90 01 04 6a 00 e8 90 01 03 ff b2 01 b8 90 01 04 e8 90 01 03 ff 84 c0 75 0a b8 90 01 04 e8 90 01 03 ff ba 90 01 04 b8 90 01 04 e8 90 01 03 ff 84 c0 74 90 01 01 33 d2 90 00 } //1
		$a_02_1 = {2f 00 6d 00 61 00 7a 00 64 00 61 00 2e 00 65 00 78 00 65 00 90 0a 50 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 0a 30 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
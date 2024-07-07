
rule TrojanDownloader_Win32_Cutwail_V{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f0 00 00 00 00 8d 45 e8 8b 55 fc 8b 4d f0 8a 14 0a 8a 4d f0 41 32 d1 e8 90 01 02 ff ff 8b 55 e8 8b 45 f4 e8 90 01 02 ff ff 8b 45 f4 ff 45 f0 ff 4d ec 75 d3 90 00 } //1
		$a_03_1 = {ba 1f 00 00 00 e8 90 01 02 ff ff 8b 45 ec e8 90 01 02 ff ff 8d 4d e8 b8 90 01 04 ba 22 00 00 00 e8 90 01 02 ff ff 8b 45 e8 90 00 } //1
		$a_02_2 = {47 45 54 20 2f 66 69 6c 65 73 2f 90 02 0a 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}
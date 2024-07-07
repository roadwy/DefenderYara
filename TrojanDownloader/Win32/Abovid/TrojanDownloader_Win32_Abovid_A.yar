
rule TrojanDownloader_Win32_Abovid_A{
	meta:
		description = "TrojanDownloader:Win32/Abovid.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 00 00 00 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 6e 61 6d 65 70 69 63 73 2e 69 6e 66 6f 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6e 61 6d 65 3d } //1
		$a_03_1 = {8b 83 04 03 00 00 89 58 74 c7 40 70 90 01 04 89 58 7c c7 40 78 90 01 04 e8 90 01 04 ba 90 01 04 8b 83 f8 02 00 00 e8 90 01 04 33 d2 8b 83 f8 02 00 00 8b 08 ff 51 64 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
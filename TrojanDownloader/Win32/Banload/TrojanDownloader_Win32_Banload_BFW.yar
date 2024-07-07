
rule TrojanDownloader_Win32_Banload_BFW{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb f8 68 70 17 00 00 e8 90 01 04 6a 00 a1 90 01 04 e8 90 01 04 50 e8 90 01 04 68 e8 03 00 00 e8 90 01 04 6a 00 a1 90 01 04 e8 90 01 04 50 e8 90 00 } //1
		$a_03_1 = {8b 55 f0 8b 83 fc 02 00 00 e8 90 01 04 b8 90 01 04 ba 90 01 04 e8 90 01 04 ff 35 90 01 04 8d 55 ec 8b 83 f8 02 00 00 e8 90 01 04 ff 75 ec 68 90 01 04 b8 90 01 04 ba 03 00 00 00 e8 90 01 04 b8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
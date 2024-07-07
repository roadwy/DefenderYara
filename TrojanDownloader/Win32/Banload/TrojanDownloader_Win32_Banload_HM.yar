
rule TrojanDownloader_Win32_Banload_HM{
	meta:
		description = "TrojanDownloader:Win32/Banload.HM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 04 50 e8 90 01 04 8b d3 8b c4 e8 90 01 04 81 c4 94 00 00 00 5b c3 90 00 } //1
		$a_03_1 = {8d 45 f8 e8 90 01 02 ff ff ff 75 f8 68 90 01 04 68 90 01 04 8d 45 fc ba 03 00 00 00 e8 90 01 04 8b 55 fc b8 90 01 04 e8 90 01 04 84 c0 74 3f 33 d2 8b 83 f8 02 00 00 e8 90 01 04 6a 01 8d 45 f0 e8 90 01 04 ff 75 f0 68 90 01 04 68 90 01 04 8d 45 f4 ba 03 00 00 00 e8 90 01 04 8b 45 f4 e8 90 01 04 50 e8 90 01 04 33 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
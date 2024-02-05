
rule TrojanDownloader_Win32_Delf_QM{
	meta:
		description = "TrojanDownloader:Win32/Delf.QM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7d 24 6a 00 6a 23 68 90 01 04 6a 00 e8 90 01 04 b8 90 01 04 ba 90 01 04 b9 00 01 00 00 e8 90 01 04 8d 4d e4 ba 01 00 00 00 a1 90 01 04 e8 90 01 7d 6a 00 6a 00 6a 00 6a 00 68 90 01 04 a1 90 01 04 50 e8 90 01 04 a3 90 01 04 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8d 45 d8 b9 90 01 04 8b 15 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
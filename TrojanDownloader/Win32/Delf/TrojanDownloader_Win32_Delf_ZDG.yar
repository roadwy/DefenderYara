
rule TrojanDownloader_Win32_Delf_ZDG{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZDG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {7b 38 46 35 33 37 45 32 41 2d 30 31 37 33 2d 34 36 41 41 2d 42 42 31 42 2d 31 45 35 45 41 34 37 44 45 36 34 34 7d } //01 00  {8F537E2A-0173-46AA-BB1B-1E5EA47DE644}
		$a_00_1 = {54 69 6d 65 44 6c 6c 5c 7a 6c 75 45 78 70 54 6f 6f 6c 73 2e 70 61 73 } //02 00  TimeDll\zluExpTools.pas
		$a_02_2 = {64 ff 30 64 89 20 8d 45 90 01 01 e8 90 01 04 ff 75 90 01 01 68 90 01 04 8d 55 90 01 01 b8 04 00 00 00 e8 90 01 04 ff 75 90 01 01 8d 45 f8 ba 03 00 00 00 e8 90 01 04 a0 90 01 04 50 8d 45 90 01 01 50 33 c9 ba 90 01 04 b8 90 01 04 e8 90 01 04 8d 45 f8 8b 55 f0 e8 90 01 04 ba 90 01 04 b9 90 01 04 8b 45 f8 e8 90 01 04 33 c0 5a 59 59 64 89 10 eb 14 90 00 } //02 00 
		$a_02_3 = {8b 45 f4 50 ba 90 01 04 b9 90 01 04 8b 45 90 01 01 8b 18 ff 53 0c 8b 45 e4 50 ba 90 01 04 b9 90 01 04 8b 45 90 01 01 8b 18 ff 53 04 83 7d e0 00 74 90 01 01 6a 00 8b 45 e0 e8 90 01 04 50 e8 90 01 04 eb 0c b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
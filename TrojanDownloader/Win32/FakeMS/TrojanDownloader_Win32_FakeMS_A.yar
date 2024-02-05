
rule TrojanDownloader_Win32_FakeMS_A{
	meta:
		description = "TrojanDownloader:Win32/FakeMS.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 6d 6d 62 68 6e 6e 25 6f 6a } //01 00 
		$a_01_1 = {8b 45 ec 39 45 e4 7d 12 8b 45 e8 03 c1 8b 55 e4 8a 14 32 30 10 ff 45 e4 eb e6 ff 45 e8 eb d9 } //01 00 
		$a_01_2 = {73 11 2b 45 f4 33 d2 b9 10 0e 00 00 f7 f1 83 f8 01 eb 12 2b 45 f4 33 d2 b9 80 51 01 00 f7 f1 } //00 00 
	condition:
		any of ($a_*)
 
}
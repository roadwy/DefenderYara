
rule TrojanDownloader_Win32_Zlob_ZWO{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZWO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c4 7c ff ff ff 33 c0 89 85 7c ff ff ff 89 45 80 89 45 84 89 45 fc 89 45 94 89 45 88 33 c0 55 68 90 01 04 64 ff 30 64 89 20 6a 00 8d 45 84 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 84 e8 90 01 04 50 a1 90 01 04 e8 90 01 04 50 e8 d4 40 ff ff 8d 4d 80 b2 9d b8 90 01 04 e8 90 01 04 8b 55 80 a1 90 01 04 e8 90 01 04 a1 90 01 04 e8 90 01 04 50 e8 d0 40 ff ff 8d 85 7c ff ff ff b9 90 01 04 8b 90 01 05 e8 90 01 04 8b 85 7c ff ff ff e8 90 01 04 50 e8 a9 40 ff ff 90 00 } //01 00 
		$a_01_1 = {f5 e9 e9 ed a7 b2 b2 ed f2 ea f8 ef f0 ed f8 fa b3 fe f2 f0 b2 } //00 00 
	condition:
		any of ($a_*)
 
}
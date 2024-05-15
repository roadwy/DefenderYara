
rule TrojanDownloader_Win32_Grandoreiro_ZY{
	meta:
		description = "TrojanDownloader:Win32/Grandoreiro.ZY,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {8b 00 0f b6 04 06 0f b6 14 1e 03 c2 25 ff 00 00 00 0f b6 14 06 8b c7 85 c0 74 90 01 01 83 e8 04 8b 00 48 85 c0 7c 90 01 01 40 33 db 30 14 1f 43 48 90 00 } //0a 00 
		$a_03_2 = {0f b7 44 50 fe 03 c3 b9 ff 00 00 00 99 f7 f9 8b f2 3b 7d ec 7d 03 47 eb 05 bf 01 00 00 00 8b 45 90 01 01 0f b7 44 78 fe 33 f0 8b de 8d 45 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 af 7a 06 80 5c 2a 00 00 b0 7a 06 80 00 00 01 00 } //04 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Gofake_A{
	meta:
		description = "TrojanDownloader:Win32/Gofake.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 45 f4 01 81 7d f4 e5 00 00 00 7e d6 83 7d ec 00 } //01 00 
		$a_01_1 = {83 45 f4 01 81 7d f4 f8 20 00 00 7e d6 8b 45 e4 89 c2 8b 45 ec 8d 48 05 } //01 00 
		$a_00_2 = {c1 e9 1f 01 c8 d1 f8 03 45 08 0f b6 00 88 02 8b 45 f4 83 c0 01 89 c2 03 55 f0 8b 45 f4 89 c1 c1 e9 1f 01 c8 d1 f8 } //00 00 
		$a_00_3 = {5d 04 00 } //00 48 
	condition:
		any of ($a_*)
 
}
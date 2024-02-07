
rule TrojanDownloader_Win32_Small_AHY{
	meta:
		description = "TrojanDownloader:Win32/Small.AHY,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b } //0a 00  microsoft_lock
		$a_02_1 = {4d 53 43 46 90 01 38 90 03 01 01 62 70 2e 64 6c 6c 2e 7a 67 78 90 00 } //0a 00 
		$a_01_2 = {25 73 73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //01 00  %ssysoption.ini
		$a_01_3 = {2e 64 6c 6c 2e 7a 67 78 2e 74 6d 70 } //01 00  .dll.zgx.tmp
		$a_01_4 = {5c 00 73 00 2e 00 65 00 78 00 65 00 2e 00 74 00 6d 00 70 00 } //00 00  \s.exe.tmp
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Small_AHY_2{
	meta:
		description = "TrojanDownloader:Win32/Small.AHY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 61 73 6b 50 69 63 2e 62 6d 70 } //01 00  MaskPic.bmp
		$a_01_1 = {33 62 37 65 35 35 35 61 37 36 35 35 33 36 61 37 } //01 00  3b7e555a765536a7
		$a_01_2 = {25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 64 5e 5e 25 6c 75 5e 5e 25 64 5e 5e 25 64 } //01 00  %d^^%d^^%d^^%d^^%d^^%d^^%d^^%d^^%d^^%lu^^%d^^%d
		$a_01_3 = {72 74 2e 6e 65 74 6b 69 } //01 00  rt.netki
		$a_03_4 = {40 77 65 6e 23 25 25 25 36 6e 00 00 26 63 68 74 3d 90 01 03 26 75 69 64 3d 90 01 03 26 6f 73 3d 90 01 04 26 61 76 3d 90 01 04 26 74 6d 3d 90 01 04 26 72 31 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Small_AHY_3{
	meta:
		description = "TrojanDownloader:Win32/Small.AHY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 25 00 64 00 2e 00 74 00 6d 00 70 00 } //01 00  %s\window%d.tmp
		$a_01_1 = {69 00 64 00 3d 00 33 00 30 00 31 00 33 00 26 00 37 00 37 00 38 00 38 00 32 00 35 00 31 00 } //01 00  id=3013&7788251
		$a_01_2 = {2f 00 59 00 6f 00 75 00 64 00 61 00 6f 00 54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 5f 00 74 00 62 00 2e 00 74 00 75 00 7a 00 69 00 2e 00 65 00 78 00 65 00 7c 00 } //01 00  /YoudaoToolbar_tb.tuzi.exe|
		$a_01_3 = {31 00 31 00 35 00 2e 00 32 00 33 00 38 00 2e 00 32 00 35 00 32 00 2e 00 31 00 31 00 33 00 2f 00 73 00 65 00 65 00 6d 00 61 00 6f 00 5f 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 7c 00 } //00 00  115.238.252.113/seemao_setup.exe|
	condition:
		any of ($a_*)
 
}
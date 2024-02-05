
rule TrojanDownloader_Win32_Obvod_K{
	meta:
		description = "TrojanDownloader:Win32/Obvod.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 2f 30 78 61 62 61 64 31 64 65 61 2e 70 68 70 3f 61 3d 25 73 26 62 3d 25 64 26 63 3d 25 64 } //01 00 
		$a_00_1 = {70 6f 70 75 70 6d 67 72 00 } //01 00 
		$a_01_2 = {88 8e 00 01 00 00 88 8e 01 01 00 00 33 ff 8b c1 33 db 99 f7 7c 24 1c 8a 1c 31 8a 04 2a 03 c3 03 c7 25 ff 00 00 00 41 8b f8 81 f9 00 01 00 00 8a 14 37 88 54 31 ff 88 1c 37 7c d3 } //00 00 
	condition:
		any of ($a_*)
 
}
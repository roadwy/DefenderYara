
rule TrojanDownloader_Win32_Merolcon_A{
	meta:
		description = "TrojanDownloader:Win32/Merolcon.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {21 64 77 6e 74 14 81 38 21 63 6c 6f 74 14 81 38 21 72 65 6d 74 } //03 00 
		$a_01_1 = {c7 00 6d 6f 64 65 83 c0 04 c7 00 3d 32 26 69 83 c0 04 c7 00 64 65 6e 74 83 c0 04 c6 00 3d } //01 00 
		$a_01_2 = {30 30 30 30 00 48 31 4e 31 42 6f 74 } //01 00  〰〰䠀丱䈱瑯
		$a_01_3 = {61 64 6d 69 6e 2f 62 6f 74 2e 70 68 70 } //01 00  admin/bot.php
		$a_00_4 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 00 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
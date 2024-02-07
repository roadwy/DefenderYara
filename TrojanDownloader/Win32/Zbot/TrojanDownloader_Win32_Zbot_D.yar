
rule TrojanDownloader_Win32_Zbot_D{
	meta:
		description = "TrojanDownloader:Win32/Zbot.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 6d 73 31 } //02 00  wms1
		$a_01_1 = {8b d3 81 e2 f0 00 00 00 c1 ea 04 83 fa 40 77 33 6a 00 68 80 00 00 00 6a 03 6a 00 8b c3 25 f0 00 00 00 c1 e8 04 } //02 00 
		$a_01_2 = {be 38 b5 41 6a 0f b7 f9 8b df 81 c3 92 3e 58 7c } //00 00 
	condition:
		any of ($a_*)
 
}
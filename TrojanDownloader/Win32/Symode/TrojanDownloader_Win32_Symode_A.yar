
rule TrojanDownloader_Win32_Symode_A{
	meta:
		description = "TrojanDownloader:Win32/Symode.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 0f b7 0d fc 74 40 00 c1 e1 07 89 0d b8 73 40 00 c7 45 fc 00 00 00 00 eb 09 8b 55 fc 83 c2 01 89 55 fc 81 7d fc 90 b2 08 00 7d } //01 00 
		$a_01_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 b8 73 40 00 c7 45 f8 10 00 00 00 0f b7 0d fe 74 40 00 83 f9 09 75 09 8b 55 f8 83 c2 08 89 55 f8 a1 b8 73 40 00 8b 4d f8 d3 e8 89 45 f8 8b 0d c8 73 40 00 03 4d fc 0f be 11 33 55 f8 a1 c8 73 40 00 03 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}
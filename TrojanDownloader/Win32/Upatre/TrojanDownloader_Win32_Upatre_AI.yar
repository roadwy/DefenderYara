
rule TrojanDownloader_Win32_Upatre_AI{
	meta:
		description = "TrojanDownloader:Win32/Upatre.AI,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {fc ad ab 33 c0 66 ad ab e2 f7 } //02 00 
		$a_03_1 = {5b 83 c3 09 e9 90 01 04 4c 6f 61 64 4c 90 00 } //01 00 
		$a_01_2 = {8b 00 fe c8 fe c4 66 3d 4c 5b 0f 84 } //01 00 
		$a_01_3 = {ff d1 2b c2 8b 08 02 cd fe c1 66 81 f9 a8 5a 75 f1 } //01 00 
		$a_01_4 = {63 25 73 25 73 00 25 73 5c 25 73 00 6f 70 65 6e 00 } //00 00 
		$a_00_5 = {80 10 00 00 } //4a f3 
	condition:
		any of ($a_*)
 
}
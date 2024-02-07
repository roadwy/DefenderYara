
rule Trojan_Win32_Downloader_CG_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8d 99 91 29 8c 88 83 c0 04 33 d3 8b 58 fc 33 da 81 c1 dc e5 2d 00 89 58 fc 8d 1c 06 3b df 76 e0 } //01 00 
		$a_00_1 = {0f b6 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 d8 e7 40 00 41 4e 75 e7 } //01 00 
		$a_80_2 = {4e 4f 31 44 61 74 65 2e 45 58 45 } //NO1Date.EXE  01 00 
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}
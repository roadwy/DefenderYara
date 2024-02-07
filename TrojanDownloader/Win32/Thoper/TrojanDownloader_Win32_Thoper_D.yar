
rule TrojanDownloader_Win32_Thoper_D{
	meta:
		description = "TrojanDownloader:Win32/Thoper.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 25 f2 00 00 66 89 4d fc 50 } //01 00 
		$a_01_1 = {81 e9 6a 3b 00 00 66 89 4d fc } //01 00 
		$a_03_2 = {57 b8 25 f2 00 00 68 90 01 04 56 66 89 44 24 1c 90 00 } //01 00 
		$a_01_3 = {81 c1 36 79 00 00 66 89 4d fc } //00 00 
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}
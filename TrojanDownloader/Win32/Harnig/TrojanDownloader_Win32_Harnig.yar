
rule TrojanDownloader_Win32_Harnig{
	meta:
		description = "TrojanDownloader:Win32/Harnig,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 3f 63 3d 25 64 00 25 73 25 73 } //01 00  猥挿┽d猥猥
		$a_01_1 = {0f 85 c5 00 00 00 8b 35 a8 10 14 13 bf 00 04 } //02 00 
		$a_01_2 = {25 73 25 73 26 69 64 3d 25 64 26 63 3d 25 64 00 25 75 00 00 25 73 25 73 25 73 00 00 25 73 3f 63 } //02 00 
		$a_01_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Partsiosity_A{
	meta:
		description = "TrojanDownloader:Win32/Partsiosity.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 76 3d 25 6c 75 26 75 76 3d 25 6c 64 26 75 63 3d 25 6c 75 26 6c 72 70 3d 25 6c 64 26 73 79 65 3d 25 6c 75 } //01 00  cv=%lu&uv=%ld&uc=%lu&lrp=%ld&sye=%lu
		$a_01_1 = {70 3a 2f 70 6c 61 79 65 72 2f 00 00 2f 70 6c 75 67 69 6e 2f } //01 00 
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 43 00 65 00 6e 00 74 00 65 00 72 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 53 00 63 00 6f 00 70 00 65 00 } //01 00 
		$a_01_3 = {8b d0 83 c4 0c 83 c7 02 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 } //01 00 
		$a_01_4 = {3f 64 6c 3d 31 00 00 00 66 6e 00 00 63 6c 00 00 63 73 00 00 25 6c 64 } //00 00 
	condition:
		any of ($a_*)
 
}
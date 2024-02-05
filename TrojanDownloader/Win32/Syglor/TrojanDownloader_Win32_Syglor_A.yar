
rule TrojanDownloader_Win32_Syglor_A{
	meta:
		description = "TrojanDownloader:Win32/Syglor.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {be 0f 00 00 00 33 ff 52 89 b5 90 01 04 89 bd 90 01 04 c6 85 90 01 04 00 e8 90 00 } //01 00 
		$a_00_1 = {26 68 61 72 64 69 64 3d 25 73 } //01 00 
		$a_00_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5d } //01 00 
		$a_00_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 39 2e 38 30 } //01 00 
		$a_00_4 = {39 35 20 4f 53 52 20 32 } //01 00 
		$a_00_5 = {31 32 33 2e 74 6d 70 } //01 00 
		$a_00_6 = {2f 2e 73 79 73 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}
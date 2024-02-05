
rule TrojanDownloader_Win32_Gobundaz_A{
	meta:
		description = "TrojanDownloader:Win32/Gobundaz.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {49 4e 46 45 43 54 20 46 41 43 45 20 4e 90 02 03 20 2d 20 90 00 } //04 00 
		$a_01_1 = {5c 73 79 73 74 2e 64 61 74 } //04 00 
		$a_01_2 = {69 6e 73 64 62 2e 70 68 70 3f 74 61 62 6c 65 3d } //01 00 
		$a_03_3 = {72 2c 2f 73 35 38 40 34 2d 32 39 73 90 01 01 71 36 32 32 3f 3c 3e 40 3b 73 2e 32 2d 32 3b 72 72 67 31 90 00 } //01 00 
		$a_01_4 = {72 32 3b 33 38 73 2d 2e 32 39 31 39 31 2e 38 2d 40 2f 3a 73 40 3d 38 3c 34 35 40 32 3e 3c 2f 72 } //00 00 
		$a_00_5 = {5d 04 00 00 da } //20 03 
	condition:
		any of ($a_*)
 
}
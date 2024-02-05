
rule TrojanDownloader_Win32_Banload_ZEL{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 90 01 04 8a 80 90 01 04 ff 24 85 90 00 } //01 00 
		$a_03_1 = {8b 0e 8b 1f 38 d9 75 90 01 01 4a 74 90 01 01 38 fd 75 90 01 01 4a 74 90 01 01 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 90 00 } //01 00 
		$a_01_2 = {74 75 62 65 6d 6f 64 65 38 32 32 2e 68 6c 70 } //01 00 
		$a_00_3 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Dihallo_A{
	meta:
		description = "TrojanDownloader:Win32/Dihallo.A,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 28 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //0a 00 
		$a_00_1 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //07 00 
		$a_00_2 = {45 32 33 33 31 39 45 34 2d 33 31 45 41 2d 34 32 32 31 2d 38 44 44 44 2d 39 39 30 45 32 37 43 42 37 35 35 46 } //05 00 
		$a_00_3 = {26 6c 69 64 3d 30 78 25 78 26 73 6c 69 64 3d 30 78 25 78 26 76 6d 3d 25 64 26 64 3d 25 23 30 34 64 25 23 30 32 64 25 23 30 32 64 26 74 3d 25 23 30 32 64 25 23 30 32 64 25 23 30 32 64 26 62 3d 25 64 26 64 64 31 3d 25 73 } //05 00 
		$a_00_4 = {6a 65 78 65 31 } //01 00 
		$a_00_5 = {6d 6f 64 65 6d } //01 00 
		$a_00_6 = {69 73 64 6e } //03 00 
		$a_01_7 = {43 3a 5c 54 45 4d 50 5c 64 2e 62 61 74 } //05 00 
		$a_01_8 = {26 6c 73 63 61 6c 3d 25 23 30 34 64 25 23 30 32 64 25 23 30 32 64 25 23 30 32 64 25 23 30 32 64 25 23 30 32 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Dihallo_A_2{
	meta:
		description = "TrojanDownloader:Win32/Dihallo.A,SIGNATURE_TYPE_PEHSTR,3e 00 3c 00 08 00 00 14 00 "
		
	strings :
		$a_01_0 = {45 32 33 33 31 39 45 34 2d 33 31 45 41 2d 34 32 32 31 2d 38 44 44 44 2d 39 39 30 45 32 37 43 42 37 35 35 46 } //14 00 
		$a_01_1 = {68 61 6c 6c 6f } //05 00 
		$a_01_2 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //05 00 
		$a_01_3 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //05 00 
		$a_01_4 = {26 6c 69 64 3d 30 78 25 78 26 73 6c 69 64 3d 30 78 25 78 26 76 6d 3d 25 64 26 64 3d 25 23 30 34 64 25 23 30 32 64 25 23 30 32 64 26 74 3d 25 23 30 32 64 25 23 30 32 64 25 23 30 32 64 26 62 3d 25 64 26 64 64 31 3d 25 73 } //05 00 
		$a_01_5 = {6a 65 78 65 31 } //01 00 
		$a_01_6 = {6d 6f 64 65 6d } //01 00 
		$a_01_7 = {69 73 64 6e } //00 00 
	condition:
		any of ($a_*)
 
}
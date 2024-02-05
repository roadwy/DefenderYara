
rule TrojanDownloader_Win32_Parkchicers_A{
	meta:
		description = "TrojanDownloader:Win32/Parkchicers.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 44 6f 77 6e 6c 6f 61 64 52 61 6e 64 6f 6d 55 72 6c 46 69 6c 65 28 29 20 53 54 41 52 54 } //02 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 31 34 2e 32 30 37 2e 31 31 32 2e 31 36 39 2f 63 6f 75 6e 74 5f 6c 6f 67 2f 6c 6f 67 2f 62 6f 6f 74 2e 70 68 70 3f 70 3d } //01 00 
		$a_01_2 = {3d 3d 20 46 2e 49 2e 4e 2e 41 2e 4c 2e 49 2e 5a 2e 41 2e 54 2e 49 2e 4f 2e 4e } //01 00 
		$a_01_3 = {45 78 65 63 75 74 65 5f 55 70 64 61 74 65 72 5f } //00 00 
	condition:
		any of ($a_*)
 
}
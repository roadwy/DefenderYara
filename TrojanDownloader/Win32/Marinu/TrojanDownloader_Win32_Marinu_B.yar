
rule TrojanDownloader_Win32_Marinu_B{
	meta:
		description = "TrojanDownloader:Win32/Marinu.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6b 66 6d 2f 67 65 74 2e 70 68 70 3f 69 64 3d 31 39 31 32 26 66 6f 72 63 65 64 6f 77 6e 6c 6f 61 64 3d 31 } //01 00 
		$a_01_1 = {2f 69 6d 67 2f 70 36 2e 6a 70 67 } //01 00 
		$a_01_2 = {2f 6d 6f 64 75 6c 65 2f 7a 35 2e 6a 70 67 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}
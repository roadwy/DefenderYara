
rule TrojanDownloader_Win32_Lisfonp_A{
	meta:
		description = "TrojanDownloader:Win32/Lisfonp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 00 64 00 6f 00 77 00 6e 00 2e 00 35 00 32 00 30 00 31 00 38 00 31 00 39 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 } //01 00 
		$a_00_1 = {52 61 6e 67 65 3a 62 79 74 65 73 3d 25 64 2d 00 2e 75 70 67 00 00 00 00 25 64 4b 42 00 00 00 00 25 2e 32 66 4d 42 } //01 00 
		$a_03_2 = {2e 74 78 74 00 00 00 00 90 02 08 2e 69 6e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Banzlirb_B{
	meta:
		description = "TrojanDownloader:Win32/Banzlirb.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 70 69 72 61 74 75 62 61 2e 65 78 65 } //01 00 
		$a_03_1 = {2e 7a 6c 69 62 90 02 20 2e 65 78 65 90 02 20 41 50 50 44 41 54 41 90 00 } //01 00 
		$a_03_2 = {2e 7a 6c 69 62 90 02 20 2e 65 78 65 90 02 20 41 56 49 53 4f 90 00 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}
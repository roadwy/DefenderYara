
rule TrojanDownloader_BAT_Bladabindi_I{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 3f 00 69 00 3d 00 } //05 00 
		$a_01_1 = {70 65 70 73 69 4b 4f 4f } //01 00 
		$a_01_2 = {5c 00 41 00 56 00 49 00 52 00 41 00 2e 00 65 00 78 00 65 00 } //00 00 
		$a_00_3 = {5d 04 00 00 4e 41 03 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}
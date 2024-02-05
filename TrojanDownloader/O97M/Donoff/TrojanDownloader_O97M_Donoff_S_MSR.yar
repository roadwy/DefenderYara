
rule TrojanDownloader_O97M_Donoff_S_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.S!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {3d 20 22 48 74 90 02 04 22 20 26 20 22 90 02 06 22 90 00 } //01 00 
		$a_02_1 = {53 74 72 54 65 6d 70 20 3d 20 53 74 72 54 65 6d 70 20 26 20 22 90 02 04 70 73 90 00 } //01 00 
		$a_02_2 = {53 68 74 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 53 74 72 4c 50 20 26 90 02 34 20 22 90 02 04 4d 53 22 20 26 20 53 74 72 54 65 6d 70 20 26 20 22 90 02 02 62 69 74 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
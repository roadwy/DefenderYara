
rule TrojanDownloader_Linux_Donoff_C{
	meta:
		description = "TrojanDownloader:Linux/Donoff.C,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 65 6d 70 46 69 6c 65 20 3d 20 74 65 6d 70 46 6f 6c 64 65 72 20 2b 20 22 5c 64 72 61 77 22 20 26 20 22 90 02 0c 2e 22 20 2b 20 22 22 20 2b 20 22 65 78 65 22 90 00 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 28 74 65 6d 70 46 69 6c 65 29 0d 0a 45 78 69 74 20 53 75 62 } //00 00 
	condition:
		any of ($a_*)
 
}
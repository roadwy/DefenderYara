
rule TrojanDownloader_O97M_Donoff_QO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 2a 2e 64 61 74 22 29 } //01 00  & "*.dat")
		$a_03_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 22 20 2b 90 02 25 2b 20 22 63 72 22 20 2b 90 02 25 2b 20 22 69 70 74 2e 53 22 20 2b 90 02 25 2b 20 22 68 65 22 20 2b 90 02 25 2b 20 22 6c 6c 22 2c 20 22 22 29 2e 52 75 6e 90 00 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 } //00 00  CreateTextFile
	condition:
		any of ($a_*)
 
}
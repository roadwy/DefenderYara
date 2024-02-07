
rule TrojanDownloader_O97M_Donoff_QP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 20 22 3a 5c 70 72 6f 22 20 2b 90 02 20 2b 20 22 67 72 61 6d 64 22 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 49 6f 6e 22 29 } //01 00  CreateObject("Ion")
		$a_01_2 = {49 45 2e 4e 61 76 69 67 61 74 65 20 22 68 74 6f 6d 2f 22 } //00 00  IE.Navigate "htom/"
	condition:
		any of ($a_*)
 
}
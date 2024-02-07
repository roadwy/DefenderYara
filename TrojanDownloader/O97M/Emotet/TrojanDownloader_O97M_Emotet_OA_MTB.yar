
rule TrojanDownloader_O97M_Emotet_OA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.OA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 35 28 90 02 35 28 22 90 02 45 77 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 35 28 22 70 22 20 2b 90 00 } //01 00 
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 35 2c 20 90 02 35 2c 20 22 22 29 90 00 } //01 00 
		$a_01_3 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 } //00 00  , MSForms, TextBox"
	condition:
		any of ($a_*)
 
}
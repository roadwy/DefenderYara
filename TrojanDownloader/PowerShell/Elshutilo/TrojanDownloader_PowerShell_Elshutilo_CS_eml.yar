
rule TrojanDownloader_PowerShell_Elshutilo_CS_eml{
	meta:
		description = "TrojanDownloader:PowerShell/Elshutilo.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0b 2c 20 22 90 02 2a 22 2c 20 22 22 29 90 00 } //01 00 
		$a_01_1 = {53 65 74 20 65 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_01_2 = {65 72 2e 52 75 6e } //01 00 
		$a_03_3 = {6c 69 6e 65 54 65 78 74 90 0a 1e 00 3d 20 90 02 0f 20 2b 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
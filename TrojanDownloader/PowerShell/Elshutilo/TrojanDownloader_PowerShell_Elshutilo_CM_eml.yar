
rule TrojanDownloader_PowerShell_Elshutilo_CM_eml{
	meta:
		description = "TrojanDownloader:PowerShell/Elshutilo.CM!eml,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //01 00  Sub Document_Open()
		$a_01_1 = {53 65 74 20 61 77 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set aw = CreateObject("Wscript.Shell")
		$a_03_2 = {61 77 2e 52 75 6e 20 74 6f 74 61 6c 90 01 01 2c 20 30 90 00 } //01 00 
		$a_03_3 = {74 6f 74 61 6c 90 01 01 20 3d 20 74 6f 74 61 6c 90 01 01 20 2b 20 22 5f 31 30 5f 22 20 2b 20 90 00 } //01 00 
		$a_03_4 = {74 6f 74 61 6c 90 01 01 20 3d 20 74 6f 74 61 6c 90 01 01 20 2b 20 90 02 50 73 20 2b 20 90 02 50 74 20 2b 20 90 02 50 61 20 2b 20 90 02 50 72 20 2b 20 90 02 50 74 20 2b 20 90 02 50 75 20 2b 20 90 02 50 70 20 2b 20 22 5f 22 20 2b 20 90 02 50 74 20 2b 20 90 02 50 61 20 2b 20 90 02 50 73 20 2b 20 90 02 50 6b 20 2b 20 22 27 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
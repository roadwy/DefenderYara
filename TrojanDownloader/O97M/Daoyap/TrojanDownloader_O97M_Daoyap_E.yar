
rule TrojanDownloader_O97M_Daoyap_E{
	meta:
		description = "TrojanDownloader:O97M/Daoyap.E,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 6f 73 6f 66 74 22 2c 20 36 29 20 2b 20 4c 65 66 74 28 22 2e 58 4d 4c 48 54 54 50 } //01 00  rosoft", 6) + Left(".XMLHTTP
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //01 00  = CreateObject("Adodb.Stream")
		$a_00_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("Shell.Application")
		$a_00_3 = {53 68 65 6c 6c 20 22 63 6d 64 20 2f 63 20 52 44 20 2f 53 20 2f 51 20 22 20 26 } //01 00  Shell "cmd /c RD /S /Q " &
		$a_02_4 = {2b 20 52 65 70 6c 61 63 65 28 22 5c 90 02 0f 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
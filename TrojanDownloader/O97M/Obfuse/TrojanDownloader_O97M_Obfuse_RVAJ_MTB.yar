
rule TrojanDownloader_O97M_Obfuse_RVAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 62 6a 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set objWshShell = CreateObject("WScript.Shell")
		$a_01_1 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d } //01 00  Range("A1").Value =
		$a_03_2 = {49 6e 53 74 72 28 90 02 64 2c 20 4d 69 64 28 90 02 64 2c 20 69 2c 20 31 29 29 90 00 } //01 00 
		$a_03_3 = {62 68 4b 71 76 7a 78 4a 55 79 20 3d 20 90 02 02 20 2f 20 90 02 02 20 2f 20 32 30 32 31 90 00 } //01 00 
		$a_03_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 90 02 64 28 22 68 90 02 04 3a 2f 2f 77 77 77 2e 6a 90 02 64 22 29 2c 20 46 61 6c 73 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
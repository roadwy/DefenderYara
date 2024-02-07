
rule TrojanDownloader_O97M_Bartallex_F{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.F,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 63 6f 6c 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 73 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 } //01 00  Set colOperatingSystems = objWMIService.ExecQuery("Select * from W
		$a_01_1 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 62 65 72 2c 20 22 6f 62 6a 41 44 4f 53 74 72 65 61 6d 2e 54 79 70 65 20 3d 20 31 } //01 00  Print #FileNumber, "objADOStream.Type = 1
		$a_01_2 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 73 2c 20 22 63 22 20 26 20 22 73 63 22 20 26 20 22 72 69 22 20 26 20 22 70 74 } //00 00  Print #FileNs, "c" & "sc" & "ri" & "pt
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Bartallex_F_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.F,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 0a 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 65 61 72 63 68 65 6e 67 69 6e 65 73 65 72 76 61 6e 74 2e 63 6f 6d 2f 61 66 66 69 6c 69 61 74 65 73 2f 66 6f 6e 74 73 2f 90 02 10 2e 74 78 74 90 00 } //0a 00 
		$a_03_1 = {73 63 6f 74 74 73 70 6f 74 73 6f 6e 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 63 65 72 74 69 66 69 63 61 74 65 73 2f 90 02 10 2e 74 78 74 90 00 } //01 00 
		$a_01_2 = {43 68 72 28 41 73 63 28 } //01 00  Chr(Asc(
		$a_01_3 = {4d 6f 64 75 6c 65 31 2e } //01 00  Module1.
		$a_01_4 = {63 69 6e 74 6f 73 68 3b 20 49 6e 74 65 6c 20 4d 61 63 20 4f 53 20 58 } //00 00  cintosh; Intel Mac OS X
	condition:
		any of ($a_*)
 
}
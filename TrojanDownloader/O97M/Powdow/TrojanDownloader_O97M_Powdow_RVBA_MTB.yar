
rule TrojanDownloader_O97M_Powdow_RVBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 22 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 7e 64 6a 58 73 66 77 45 46 2e 74 78 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 7e 64 6a 58 73 66 77 45 46 2e 76 62 65 22 2c 20 30 2c } //01 00  .Run("certutil -decode C:\ProgramData\~djXsfwEF.txt C:\ProgramData\~djXsfwEF.vbe", 0,
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 27 57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 28 67 74 33 29 2c 20 30 } //01 00 
		$a_01_2 = {74 73 2e 57 72 69 74 65 4c 69 6e 65 20 22 50 54 31 65 49 33 35 41 3d 22 } //01 00  ts.WriteLine "PT1eI35A="
		$a_01_3 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //00 00  document_open()
	condition:
		any of ($a_*)
 
}
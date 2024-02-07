
rule TrojanDownloader_O97M_Powdow_RVCB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {78 78 78 78 78 78 5f 2e 5f 6c 6f 61 64 28 22 68 74 74 70 90 02 64 2e 74 78 74 22 29 78 78 78 78 78 78 5f 2e 5f 74 72 61 6e 73 66 6f 72 6d 6e 6f 64 65 78 78 78 78 78 78 65 6e 64 73 75 62 90 00 } //01 00 
		$a_01_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 32 39 33 33 62 66 39 30 2d 37 62 33 36 2d 31 31 64 32 2d 62 32 30 65 2d 30 30 63 30 34 66 39 38 33 65 36 30 7d 22 29 3a 3a 3a 3a 3a 3a 3a 3a 3a 78 78 78 78 78 78 5f 2e 5f 61 73 79 6e 63 3d 66 61 6c 73 65 3a 3a } //01 00  createobject("new:{2933bf90-7b36-11d2-b20e-00c04f983e60}"):::::::::xxxxxx_._async=false::
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //00 00  workbook_open()::
	condition:
		any of ($a_*)
 
}
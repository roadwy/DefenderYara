
rule TrojanDownloader_O97M_Obfuse_FG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 46 69 6c 65 57 28 53 74 72 50 74 72 28 22 43 3a 5c 46 4d 4b 53 4a 45 55 5c 90 02 0f 2e 42 41 54 22 29 90 00 } //01 00 
		$a_03_1 = {77 73 63 72 69 70 74 20 43 3a 5c 46 4d 4b 53 4a 45 55 5c 90 02 0f 2e 4a 53 45 22 90 00 } //01 00 
		$a_00_2 = {53 65 74 20 64 6f 63 4e 65 77 20 3d 20 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 28 73 74 72 54 65 6d 70 6c 61 74 65 4e 61 6d 65 29 } //01 00  Set docNew = Documents.Add(strTemplateName)
		$a_00_3 = {64 6f 63 4e 65 77 2e 41 63 74 69 76 61 74 65 } //00 00  docNew.Activate
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Hancitor_EOAH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.EOAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 22 5c 71 71 2e 64 6f 63 22 2c } //01 00  & "\qq.doc",
		$a_01_1 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //01 00  Call Search(MyFSO.GetFolder(asda), hdv)
		$a_01_2 = {44 69 6d 20 64 66 67 64 67 64 67 } //01 00  Dim dfgdgdg
		$a_01_3 = {44 69 6d 20 75 75 75 75 63 } //01 00  Dim uuuuc
		$a_01_4 = {43 61 6c 6c 20 6e 61 6d 28 68 64 76 29 } //00 00  Call nam(hdv)
	condition:
		any of ($a_*)
 
}
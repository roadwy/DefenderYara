
rule TrojanDownloader_O97M_Ursnif_AU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 10 20 26 20 90 02 10 20 26 20 90 02 10 20 26 20 22 70 22 20 26 20 22 5c 22 20 26 20 22 5c 90 02 08 2e 78 73 6c 22 2c 20 31 29 90 00 } //1
		$a_03_1 = {43 61 6c 6c 20 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 40 28 90 02 08 2c 20 32 29 90 00 } //1
		$a_01_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 74 69 76 65 57 69 6e 64 6f 77 2e 50 61 6e 65 73 28 31 29 2e 50 61 67 65 73 2e 43 6f 75 6e 74 } //1 ActiveDocument.ActiveWindow.Panes(1).Pages.Count
		$a_01_3 = {2e 54 65 78 74 } //1 .Text
		$a_01_4 = {3d 20 22 22 } //1 = ""
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
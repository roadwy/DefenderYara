
rule TrojanDownloader_O97M_IcedID_ERY_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.ERY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 72 6d 2e 63 6c 69 63 6b 20 22 72 69 70 74 2e 73 68 22 } //01 00  frm.click "ript.sh"
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 22 20 26 20 90 02 25 20 26 20 22 65 6c 6c 22 29 2e 65 78 65 63 28 72 65 76 28 74 69 74 6c 65 29 29 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_01_2 = {3d 20 53 70 6c 69 74 28 72 65 76 28 74 69 74 6c 65 29 2c 20 22 20 22 29 } //01 00  = Split(rev(title), " ")
		$a_01_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 } //01 00  = ActiveDocument.BuiltInDocumentProperties("title")
		$a_01_4 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 31 27 3e 66 54 74 6c } //00 00  <html><body><div id='content1'>fTtl
	condition:
		any of ($a_*)
 
}
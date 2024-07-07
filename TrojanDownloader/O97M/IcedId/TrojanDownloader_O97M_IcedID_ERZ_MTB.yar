
rule TrojanDownloader_O97M_IcedID_ERZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.ERZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 31 22 2c 20 22 56 42 22 2c 20 22 69 74 79 5c 41 63 63 65 73 73 31 4f 4d 22 29 } //1 = Replace("1", "VB", "ity\Access1OM")
		$a_01_2 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //1 .Documents.Add.VBProject.VBComponents("ThisDocument").CodeModule
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
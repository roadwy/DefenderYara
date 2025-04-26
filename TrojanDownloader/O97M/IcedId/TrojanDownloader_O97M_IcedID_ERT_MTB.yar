
rule TrojanDownloader_O97M_IcedID_ERT_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.ERT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_1 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //1 .Documents.Add.VBProject.VBComponents("ThisDocument").CodeModule
		$a_03_2 = {31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 90 0c 02 00 45 6e 64 20 57 69 74 68 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 28 22 72 61 77 74 66 6f 53 5c 52 45 53 55 5f 54 4e 45 52 22 29 20 26 20 22 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 } //1 StrReverse("rawtfoS\RESU_TNER") & "e\Microsoft\Office\"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule TrojanDownloader_O97M_IcedID_BIK_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.BIK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 61 71 4d 58 5a 39 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //1 = Split(aqMXZ9(frm.paths.text), "|")
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 28 [0-0a] 29 } //1
		$a_03_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 76 56 66 65 62 22 2c 20 [0-0a] 20 26 20 22 20 22 20 26 20 [0-0a] 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 [0-0a] 20 26 } //1
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
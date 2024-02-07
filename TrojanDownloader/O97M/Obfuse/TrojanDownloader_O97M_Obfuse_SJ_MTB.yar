
rule TrojanDownloader_O97M_Obfuse_SJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 68 74 74 70 73 3a 2f 2f 90 02 25 2f 6c 73 61 73 73 2e 65 78 65 22 90 00 } //01 00 
		$a_01_1 = {6c 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 2b 20 22 5c 6c 73 61 73 73 2e 65 78 65 22 } //01 00  l = ActiveDocument.Path + "\lsass.exe"
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //01 00  = CreateObject("Microsoft.XMLHTTP")
		$a_03_3 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 90 02 05 2c 20 46 61 6c 73 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //01 00  'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_01_1 = {57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 41 63 74 69 76 61 74 65 } //01 00  Worksheets(1).Activate
		$a_03_2 = {3d 20 52 61 6e 67 65 28 90 02 02 29 2e 43 6f 6d 6d 65 6e 74 2e 54 65 78 74 90 00 } //01 00 
		$a_03_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 52 61 6e 67 65 28 90 02 02 29 2e 43 6f 6d 6d 65 6e 74 2e 54 65 78 74 29 90 00 } //01 00 
		$a_03_4 = {2e 45 78 65 63 20 28 53 74 72 52 65 76 65 72 73 65 28 90 02 07 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
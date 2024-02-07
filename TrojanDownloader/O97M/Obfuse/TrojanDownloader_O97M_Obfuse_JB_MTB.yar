
rule TrojanDownloader_O97M_Obfuse_JB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 4d 73 67 42 6f 78 28 22 45 72 72 6f 72 3a 22 20 26 20 76 62 43 72 4c 66 20 26 20 22 43 6f 6e 74 65 6e 74 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65 22 29 } //01 00  = MsgBox("Error:" & vbCrLf & "Content not available")
		$a_03_1 = {2e 54 65 78 74 42 6f 78 90 02 01 2e 54 65 78 74 90 00 } //01 00 
		$a_01_2 = {3d 20 22 4e 65 77 4d 61 63 72 6f 73 31 22 } //01 00  = "NewMacros1"
		$a_03_3 = {3d 20 47 65 74 54 69 63 6b 43 6f 75 6e 74 20 2b 20 28 90 02 12 20 2a 20 31 30 30 30 29 90 00 } //01 00 
		$a_03_4 = {3d 20 4d 69 64 28 90 02 09 2c 20 31 2c 90 00 } //01 00 
		$a_03_5 = {53 68 65 6c 6c 90 02 10 20 26 90 00 } //01 00 
		$a_01_6 = {4d 6f 64 20 2d } //01 00  Mod -
		$a_01_7 = {49 66 20 53 65 63 6f 6e 64 28 22 } //00 00  If Second("
	condition:
		any of ($a_*)
 
}
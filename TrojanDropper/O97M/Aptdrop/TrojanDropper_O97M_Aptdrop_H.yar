
rule TrojanDropper_O97M_Aptdrop_H{
	meta:
		description = "TrojanDropper:O97M/Aptdrop.H,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 3d 20 46 72 65 65 46 69 6c 65 } //01 00   = FreeFile
		$a_00_1 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 76 62 61 5f 6d 61 63 72 6f 2e 65 78 65 22 } //00 00   = Environ("TMP") & "\vba_macro.exe"
	condition:
		any of ($a_*)
 
}
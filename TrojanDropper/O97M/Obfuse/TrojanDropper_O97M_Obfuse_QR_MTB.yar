
rule TrojanDropper_O97M_Obfuse_QR_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.QR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c 90 02 0a 2e 63 6d 64 22 90 0a 2c 00 53 74 61 72 74 50 72 6f 63 65 73 73 20 22 63 3a 5c 90 00 } //01 00 
		$a_03_1 = {6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c 90 02 0a 2e 78 6d 6c 22 90 0a 1f 00 22 63 3a 5c 90 00 } //01 00 
		$a_00_2 = {44 6f 63 75 6d 65 6e 74 73 2e 41 64 64 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e } //01 00  Documents.Add(ActiveDocument.
		$a_03_3 = {20 3d 20 22 63 3a 5c 6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c 90 02 05 5c 61 63 74 69 76 65 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_EncDoc_VI_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 2e 2e 2e 2e 68 74 61 2e 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 26 6c 74 3b 22 2c 20 22 22 29 } //01 00  .....hta.", Replace(ActiveDocument.Range.Text, "&lt;", "")
		$a_01_1 = {2e 72 75 6e 20 77 6f 72 64 52 61 70 4d 69 63 72 6f 73 6f 66 74 } //01 00  .run wordRapMicrosoft
		$a_01_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}
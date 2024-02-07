
rule TrojanDropper_O97M_Powdow_RVA_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 65 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 90 02 14 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 22 20 2b 20 90 02 14 20 2b 20 22 65 6c 6c 22 29 90 00 } //01 00 
		$a_01_2 = {2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 } //01 00  .BuiltInDocumentProperties("keywords").Value
		$a_01_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 5f 66 22 } //01 00  ActiveDocument.Content.Find.Execute FindText:="_f"
		$a_01_4 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 0d 0a 6d 61 69 6e 2e 6b 61 72 6f 6c 69 6e 65 20 28 22 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
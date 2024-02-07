
rule TrojanDropper_O97M_Obfuse_KC_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.KC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 31 33 2e 78 6c 73 78 22 } //01 00  = Environ("TEMP") & "\13.xlsx"
		$a_01_1 = {3d 20 54 65 6d 70 4e 61 6d 65 20 2b 20 22 2e 7a 69 70 22 } //01 00  = TempName + ".zip"
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 27 26 20 22 5c 55 6e 7a 54 6d 70 22 } //01 00  = Environ("TEMP") '& "\UnzTmp"
		$a_01_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //01 00  = Environ("APPDATA")
		$a_03_4 = {2b 20 22 5c 90 02 12 2e 64 6c 6c 22 90 00 } //01 00 
		$a_01_5 = {2e 49 74 65 6d 28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 69 6e 22 29 } //00 00  .Item("xl\embeddings\oleObject1.bin")
	condition:
		any of ($a_*)
 
}
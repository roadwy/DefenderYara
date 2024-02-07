
rule TrojanDropper_O97M_Hancitor_JOAE_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 50 72 69 6d 65 72 31 28 46 6f 6c 64 65 72 20 26 20 22 5c 22 20 26 20 66 31 2e 4e 61 6d 65 20 26 20 22 5c 22 29 } //01 00  Call Primer1(Folder & "\" & f1.Name & "\")
		$a_01_1 = {53 75 62 20 53 75 62 66 6f 6c 64 65 72 73 5f 69 6e 28 46 6f 6c 64 65 72 24 29 } //01 00  Sub Subfolders_in(Folder$)
		$a_01_2 = {43 61 6c 6c 20 62 76 78 66 63 73 64 } //01 00  Call bvxfcsd
		$a_01_3 = {44 69 6d 20 66 73 6f 2c 20 6d 79 46 6f 6c 64 65 72 2c 20 6d 79 46 69 6c 65 2c 20 6d 79 46 69 6c 65 73 28 29 2c 20 69 } //01 00  Dim fso, myFolder, myFile, myFiles(), i
		$a_01_4 = {43 61 6c 6c 20 53 75 62 66 6f 6c 64 65 72 73 5f 69 6e 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 22 5c 4c 6f 63 61 6c 5c 22 20 26 20 22 54 65 6d 70 22 29 } //00 00  Call Subfolders_in(Left(uuuuc, ntgs) & "\Local\" & "Temp")
	condition:
		any of ($a_*)
 
}
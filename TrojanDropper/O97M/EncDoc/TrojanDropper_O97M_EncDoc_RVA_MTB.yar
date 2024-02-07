
rule TrojanDropper_O97M_EncDoc_RVA_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 66 31 30 31 29 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 66 75 6c 6c 70 61 74 68 2c 20 38 2c 20 30 29 } //05 00  CreateObject(f101).CreateTextFile(fullpath, 8, 0)
		$a_01_1 = {4c 65 6e 28 41 30 31 29 20 54 68 65 6e 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 77 73 31 29 2e 52 75 6e 20 66 75 6c 6c 70 61 74 68 } //05 00  Len(A01) Then CreateObject(ws1).Run fullpath
		$a_01_2 = {22 5c 6f 70 65 6e 2e 76 62 22 0d 0a 66 75 6c 6c 70 61 74 68 20 3d 20 66 75 6c 6c 70 61 74 68 31 31 20 2b 20 22 73 22 } //05 00 
		$a_01_3 = {66 31 30 30 2e 57 72 69 74 65 20 41 63 74 69 76 65 53 68 65 65 74 2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 32 2e 54 65 78 74 52 61 6e 67 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } //05 00  f100.Write ActiveSheet.Shapes(1).TextFrame2.TextRange.Characters.Text
		$a_01_4 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 66 75 6c 6c 70 61 74 68 31 30 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 } //00 00 
	condition:
		any of ($a_*)
 
}
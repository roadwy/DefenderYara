
rule TrojanDropper_O97M_GraceWire_AI_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //1 #If VBA7 Then
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 57 69 6e 64 6f 77 4c 6f 6e 67 20 5f } //1 Private Declare PtrSafe Function GetWindowLong _
		$a_03_2 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29 } //1
		$a_01_3 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79 } //1 ThisWorkbook.Sheets.Copy
		$a_03_4 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-25] 43 61 6c 6c 20 49 49 74 6d 73 2e 52 65 6d 6f 76 65 28 4b 65 79 29 } //1
		$a_01_5 = {55 6e 6c 6f 61 64 20 4d 2e 65 } //1 Unload M.e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
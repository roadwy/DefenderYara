
rule TrojanDownloader_O97M_Ursnif_UCMN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.UCMN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 20 28 22 22 20 26 20 22 46 22 20 26 20 33 29 } //1 Run ("" & "F" & 3)
		$a_01_1 = {70 65 72 5f 75 20 3d 20 53 70 6c 69 74 28 6a 2c 20 22 22 20 26 20 22 62 22 29 } //1 per_u = Split(j, "" & "b")
		$a_01_2 = {4c 6d 65 65 74 20 3d 20 45 63 63 6f 5f 6c 61 3a 20 4c 6d 65 65 74 20 3d 20 22 3d 22 } //1 Lmeet = Ecco_la: Lmeet = "="
		$a_01_3 = {51 75 65 73 74 6f 20 3d 20 22 54 22 20 26 20 69 6e 67 6c 65 73 65 20 26 20 22 4f 22 20 26 20 22 28 29 } //1 Questo = "T" & inglese & "O" & "()
		$a_01_4 = {69 6e 67 6c 65 73 65 20 3d 20 45 63 63 6f 5f 6c 61 20 26 20 22 52 4e } //1 inglese = Ecco_la & "RN
		$a_01_5 = {45 78 63 65 6c 34 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 28 42 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 28 31 29 29 29 2e 4e 61 6d 65 20 3d 20 45 63 63 6f 5f 6c 61 3a 20 6c 5f 65 73 70 65 72 69 65 6e 7a 61 } //1 Excel4MacroSheets.Add(Before:=Worksheets((1))).Name = Ecco_la: l_esperienza
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
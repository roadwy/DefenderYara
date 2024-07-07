
rule TrojanDropper_O97M_Farheyt_A{
	meta:
		description = "TrojanDropper:O97M/Farheyt.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 65 79 20 28 32 29 0d 0a 53 68 65 6c 6c 20 28 54 45 58 29 0d 0a 48 65 79 20 28 31 29 } //1
		$a_00_1 = {53 75 62 20 48 65 79 28 4b 61 6c 61 6d 61 6e 61 20 41 73 20 4c 6f 6e 67 29 } //1 Sub Hey(Kalamana As Long)
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 53 61 76 65 41 73 52 54 46 28 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Function SaveAsRTF(Name As String)
		$a_00_3 = {44 6f 20 57 68 69 6c 65 20 54 69 6d 65 72 20 3c 20 4a 68 62 68 64 73 } //1 Do While Timer < Jhbhds
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule TrojanDropper_O97M_Farheyt_A_2{
	meta:
		description = "TrojanDropper:O97M/Farheyt.A,SIGNATURE_TYPE_MACROHSTR_EXT,20 00 20 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 4e 61 6d 65 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 52 54 46 } //1 ActiveDocument.SaveAs FileName:=Name, FileFormat:=wdFormatRTF
		$a_01_1 = {53 61 76 65 41 73 52 54 46 28 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 SaveAsRTF(Name As String)
		$a_01_2 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 28 54 43 41 29 } //10 .Documents.Open(TCA)
		$a_01_3 = {54 4d 50 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 54 45 4d 50 22 29 } //10 TMP = Environ$("TEMP")
		$a_01_4 = {54 4d 50 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 54 45 22 20 2b 20 22 4d 50 22 29 } //10 TMP = Environ$("TE" + "MP")
		$a_01_5 = {54 45 58 20 3d 20 54 4d 50 20 2b 20 22 } //10 TEX = TMP + "
		$a_01_6 = {54 4d 50 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 22 20 26 20 22 54 45 4d 50 22 29 } //10 TMP = Environ$("" & "TEMP")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=32
 
}
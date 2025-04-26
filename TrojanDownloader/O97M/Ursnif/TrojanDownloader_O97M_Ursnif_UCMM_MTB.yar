
rule TrojanDownloader_O97M_Ursnif_UCMM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.UCMM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4d 61 6c 69 5f 69 28 52 20 41 73 20 53 74 72 69 6e 67 2c 20 53 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74 } //1 Public Function Mali_i(R As String, S As Long) As Variant
		$a_01_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 51 75 65 73 74 61 5f 63 61 72 74 65 6c 6c 61 5f 64 69 5f 6c 61 76 6f 72 6f } //1 Attribute VB_Name = "Questa_cartella_di_lavoro
		$a_01_2 = {52 65 44 69 6d 20 4c 28 30 20 54 6f 20 43 4c 6e 67 28 28 41 69 69 28 52 29 20 2f 20 53 29 20 2d 20 31 29 29 } //1 ReDim L(0 To CLng((Aii(R) / S) - 1))
		$a_01_3 = {46 6f 72 20 45 20 3d 20 31 20 54 6f 20 41 69 69 28 52 29 20 53 74 65 70 20 53 } //1 For E = 1 To Aii(R) Step S
		$a_01_4 = {4c 28 46 29 20 3d 20 4d 69 64 28 52 2c 20 45 2c 20 53 29 3a 20 46 20 3d 20 46 20 2b 20 31 } //1 L(F) = Mid(R, E, S): F = F + 1
		$a_01_5 = {46 75 6e 63 74 69 6f 6e 20 76 65 72 73 69 6f 6e 65 28 75 6e 20 41 73 20 53 74 72 69 6e 67 2c 20 75 20 41 73 20 49 6e 74 65 67 65 72 29 } //1 Function versione(un As String, u As Integer)
		$a_01_6 = {75 20 3d 20 52 3a 20 53 68 65 65 74 73 28 31 29 2e 5b 46 34 5d 2e 46 6f 72 6d 75 6c 61 4c 6f 63 61 6c 20 3d 20 75 6e } //1 u = R: Sheets(1).[F4].FormulaLocal = un
		$a_01_7 = {6e 6f 73 74 72 69 20 3d 20 4c 6d 65 65 74 20 26 20 22 52 22 20 26 20 22 49 22 } //1 nostri = Lmeet & "R" & "I"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
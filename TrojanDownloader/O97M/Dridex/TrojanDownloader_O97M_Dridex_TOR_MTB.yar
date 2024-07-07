
rule TrojanDownloader_O97M_Dridex_TOR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.TOR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 43 6f 6e 74 72 6f 6c 20 3d 20 22 73 74 61 6d 70 61 5f 73 61 6c 76 65 5f 70 61 67 6f 2c 20 32 33 2c 20 30 2c 20 4d 53 46 6f 72 6d 73 2c 20 4d 75 6c 74 69 50 61 67 65 22 } //1 Attribute VB_Control = "stampa_salve_pago, 23, 0, MSForms, MultiPage"
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 73 70 68 65 72 65 43 68 61 74 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Function sphereChat() As String
		$a_01_2 = {73 70 68 65 72 65 43 68 61 74 20 3d 20 22 72 65 76 69 73 22 } //1 sphereChat = "revis"
		$a_01_3 = {6d 20 3d 20 22 54 4f 52 4e 4f 28 29 22 3a 20 53 68 65 65 74 73 28 61 74 29 2e 43 65 6c 6c 73 28 36 2c 20 61 74 29 2e 76 61 6c 75 65 20 3d 20 6a 20 26 20 6d 3a } //1 m = "TORNO()": Sheets(at).Cells(6, at).value = j & m:
		$a_01_4 = {53 68 65 65 74 73 28 61 74 29 2e 43 65 6c 6c 73 28 61 74 2c 20 61 74 29 2e 4e 61 6d 65 20 3d 20 73 70 68 65 72 65 43 68 61 74 20 26 20 22 73 69 6f 6e 65 22 3a 20 65 64 20 3d 20 61 74 20 2a 20 33 3a } //1 Sheets(at).Cells(at, at).Name = sphereChat & "sione": ed = at * 3:
		$a_01_5 = {46 6f 72 20 45 61 63 68 20 6c 20 49 6e 20 41 63 74 69 76 65 53 68 65 65 74 2e 55 73 65 64 52 61 6e 67 65 2e 53 70 65 63 69 61 6c 43 65 6c 6c 73 28 78 6c 43 65 6c 6c 54 79 70 65 43 6f 6e 73 74 61 6e 74 73 29 3a 20 62 20 3d 20 62 20 26 20 6c 3a 20 4e 65 78 74 } //1 For Each l In ActiveSheet.UsedRange.SpecialCells(xlCellTypeConstants): b = b & l: Next
		$a_01_6 = {53 75 62 20 4c 6f 67 69 63 61 28 29 } //1 Sub Logica()
		$a_01_7 = {67 20 3d 20 52 75 6e 28 22 22 20 26 20 73 70 68 65 72 65 43 68 61 74 20 26 20 22 73 69 6f 6e 65 22 29 } //1 g = Run("" & sphereChat & "sione")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
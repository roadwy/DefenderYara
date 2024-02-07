
rule TrojanDownloader_O97M_Obfuse_HB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 49 6e 53 74 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 28 6a 29 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 45 72 72 6f 72 22 29 20 54 68 65 6e } //01 00  If InStr(ActiveDocument.Paragraphs(j).Range.Text, "Error") Then
		$a_01_1 = {49 66 20 49 6e 53 74 72 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 28 6a 29 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 76 69 65 77 20 74 68 69 73 22 29 20 54 68 65 6e } //01 00  If InStr(ActiveDocument.Paragraphs(j).Range.Text, "view this") Then
		$a_01_2 = {44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 65 6e 64 4d 65 73 73 61 67 65 20 4c 69 62 20 22 41 63 65 33 32 22 20 41 6c 69 61 73 20 5f } //01 00  Declare PtrSafe Function SendMessage Lib "Ace32" Alias _
		$a_01_3 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } //01 00  (Environ("TEMP"))
		$a_01_4 = {3d 20 22 76 65 72 69 6e 73 74 65 72 65 2e 78 6c 73 22 } //00 00  = "verinstere.xls"
	condition:
		any of ($a_*)
 
}
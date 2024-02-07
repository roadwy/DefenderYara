
rule TrojanDownloader_O97M_Qakbot_DOLL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 73 73 61 61 49 6e 69 74 57 6f 72 6b 62 6f 6f 6b 73 73 61 61 28 29 } //01 00  Private Sub ssaaInitWorkbookssaa()
		$a_01_1 = {45 78 63 65 6c 34 49 6e 74 6c 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 2e 4e 61 6d 65 20 3d 20 22 42 6f 6f 6c 74 } //01 00  Excel4IntlMacroSheets.Add.Name = "Boolt
		$a_01_2 = {53 68 65 65 74 73 28 22 42 6f 6f 6c 74 22 29 2e 52 61 6e 67 65 28 22 49 31 31 22 29 20 3d 20 22 4a 22 20 26 20 22 4a 22 20 26 20 22 43 22 20 26 20 22 43 22 20 26 20 22 42 22 20 26 20 22 42 } //01 00  Sheets("Boolt").Range("I11") = "J" & "J" & "C" & "C" & "B" & "B
		$a_01_3 = {53 68 65 65 74 73 28 22 42 6f 6f 6c 74 22 29 2e 52 61 6e 67 65 28 22 49 31 32 22 29 20 3d 20 22 4b 6f 70 61 73 74 } //01 00  Sheets("Boolt").Range("I12") = "Kopast
		$a_01_4 = {3d 20 4a 74 72 75 68 72 64 72 67 64 67 20 26 20 61 67 61 64 66 67 20 26 20 64 66 64 73 61 66 20 26 20 22 32 } //01 00  = Jtruhrdrgdg & agadfg & dfdsaf & "2
		$a_01_5 = {4a 74 72 75 68 72 64 72 67 64 67 20 3d 20 22 72 65 22 20 26 20 22 67 73 22 20 26 20 22 76 72 22 20 26 20 22 33 32 } //00 00  Jtruhrdrgdg = "re" & "gs" & "vr" & "32
	condition:
		any of ($a_*)
 
}
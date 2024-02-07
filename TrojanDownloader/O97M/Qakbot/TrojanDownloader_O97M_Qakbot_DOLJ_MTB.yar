
rule TrojanDownloader_O97M_Qakbot_DOLJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.DOLJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 42 6f 6f 6c 74 22 29 2e 52 61 6e 67 65 28 22 48 33 22 29 } //01 00  Application.Run Sheets("Boolt").Range("H3")
		$a_01_1 = {53 68 65 65 74 73 28 22 42 6f 6f 6c 74 22 29 2e 52 61 6e 67 65 28 22 49 31 30 22 29 20 3d 20 22 55 22 20 26 20 22 52 4c 22 20 26 20 22 44 6f 22 20 26 20 22 77 6e 22 20 26 20 22 6c 6f 22 20 26 20 22 61 64 22 20 26 20 22 54 6f 22 20 26 20 22 46 69 22 20 26 20 22 6c 65 22 20 26 20 22 41 } //01 00  Sheets("Boolt").Range("I10") = "U" & "RL" & "Do" & "wn" & "lo" & "ad" & "To" & "Fi" & "le" & "A
		$a_01_2 = {3d 20 4e 6f 6c 65 72 74 2e 4c 61 62 65 6c 35 2e 43 61 70 74 69 6f 6e 20 26 20 22 31 } //01 00  = Nolert.Label5.Caption & "1
		$a_01_3 = {3d 4b 6f 70 61 73 74 28 30 2c 48 32 34 26 4b 31 37 26 4b 31 38 2c 47 31 30 2c 30 2c 30 29 } //01 00  =Kopast(0,H24&K17&K18,G10,0,0)
		$a_01_4 = {43 22 20 26 20 22 65 6c 22 20 26 20 22 6f 64 22 20 26 20 22 2e 77 22 20 26 20 22 61 63 } //00 00  C" & "el" & "od" & ".w" & "ac
	condition:
		any of ($a_*)
 
}
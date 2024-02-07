
rule TrojanDownloader_O97M_Qakbot_RVD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 46 72 65 64 69 22 29 2e 52 61 6e 67 65 28 22 48 33 22 29 } //01 00  Application.Run Sheets("Fredi").Range("H3")
		$a_01_1 = {4e 6f 6c 65 72 74 2e 4e 69 6b 61 73 2e 43 61 70 74 69 6f 6e 20 26 20 22 20 2e 2e 5c 43 65 6c 6f 64 2e 77 61 63 22 } //01 00  Nolert.Nikas.Caption & " ..\Celod.wac"
		$a_01_2 = {2e 52 61 6e 67 65 28 22 49 31 30 22 29 20 3d 20 22 55 22 20 26 20 22 52 4c 22 20 26 20 22 44 6f 22 20 26 20 22 77 6e 22 20 26 20 22 6c 6f 22 20 26 20 22 61 64 22 20 26 20 22 54 6f 22 20 26 20 22 46 69 22 20 26 20 22 6c 65 22 20 26 20 22 41 22 } //01 00  .Range("I10") = "U" & "RL" & "Do" & "wn" & "lo" & "ad" & "To" & "Fi" & "le" & "A"
		$a_01_3 = {53 68 65 65 74 73 28 22 46 72 65 64 69 22 29 2e 52 61 6e 67 65 28 22 41 31 3a 4d 31 30 30 22 29 2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 76 62 57 68 69 74 65 } //00 00  Sheets("Fredi").Range("A1:M100").Font.Color = vbWhite
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Qakbot_KAQA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.KAQA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 79 74 72 75 79 20 3d 20 22 52 22 20 26 20 22 45 22 20 26 20 22 47 22 20 26 20 22 49 22 20 26 20 22 53 54 45 52 } //1 Bytruy = "R" & "E" & "G" & "I" & "STER
		$a_01_1 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 28 22 4b 31 38 22 29 20 3d 20 22 2e 64 22 20 26 20 22 61 22 20 26 20 22 74 } //1 Sheets("Diolare").Range("K18") = ".d" & "a" & "t
		$a_01_2 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 28 22 41 31 3a 4d 31 30 30 22 29 2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 76 62 57 68 69 74 65 } //1 Sheets("Diolare").Range("A1:M100").Font.Color = vbWhite
		$a_01_3 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 28 22 49 31 32 22 29 20 3d 20 22 42 79 75 6b 69 6c 6f 73 } //1 Sheets("Diolare").Range("I12") = "Byukilos
		$a_01_4 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 28 22 49 31 39 22 29 20 3d 20 4c 6f 69 75 20 26 20 22 32 } //1 Sheets("Diolare").Range("I19") = Loiu & "2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule TrojanDownloader_O97M_Qakbot_ANML_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ANML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 4b 31 38 22 29 20 3d 20 22 2e 64 61 74 } //1 Sheets("Nosto").Range("K18") = ".dat
		$a_01_1 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 47 31 30 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 34 2e 43 61 70 74 69 6f 6e } //1 Sheets("Nosto").Range("G10") = UserForm4.Caption
		$a_01_2 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 47 31 31 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 34 2e 43 61 70 74 69 6f 6e 20 26 20 22 31 } //1 Sheets("Nosto").Range("G11") = UserForm4.Caption & "1
		$a_01_3 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 47 31 32 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 34 2e 43 61 70 74 69 6f 6e 20 26 20 22 32 } //1 Sheets("Nosto").Range("G12") = UserForm4.Caption & "2
		$a_01_4 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 49 31 38 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 33 2e 43 61 70 74 69 6f 6e 20 26 20 22 31 } //1 Sheets("Nosto").Range("I18") = UserForm3.Caption & "1
		$a_01_5 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 49 31 39 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 33 2e 43 61 70 74 69 6f 6e 20 26 20 22 32 } //1 Sheets("Nosto").Range("I19") = UserForm3.Caption & "2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
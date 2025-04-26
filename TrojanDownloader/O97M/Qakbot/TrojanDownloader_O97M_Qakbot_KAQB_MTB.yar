
rule TrojanDownloader_O97M_Qakbot_KAQB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.KAQB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 } //1 Sheets("Diolare").Range
		$a_01_1 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 42 6c 6f 73 74 2e 43 61 70 74 69 6f 6e } //1 = UserForm2.Blost.Caption
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 } //1 Application.Run Sheets("Diolare").Range
		$a_01_3 = {53 68 65 65 74 73 28 22 44 61 73 68 62 6f 61 72 64 22 29 2e 50 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 53 68 65 65 74 73 28 22 44 61 73 68 62 6f 61 72 64 22 29 2e 52 61 6e 67 65 } //1 Sheets("Dashboard").Protect Password:=Sheets("Dashboard").Range
		$a_01_4 = {53 68 65 65 74 73 28 22 44 69 6f 6c 61 72 65 22 29 2e 52 61 6e 67 65 28 22 48 32 35 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 32 2e 4c 61 62 65 6c 33 2e 43 61 70 74 69 6f 6e } //1 Sheets("Diolare").Range("H25") = UserForm2.Label3.Caption
		$a_01_5 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 4c 61 62 65 6c 35 2e 43 61 70 74 69 6f 6e 20 26 20 22 32 22 } //1 = UserForm2.Label5.Caption & "2"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
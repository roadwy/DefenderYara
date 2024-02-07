
rule TrojanDownloader_O97M_Qakbot_ANMN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ANMN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 39 22 29 20 3d 20 22 3d 22 20 26 20 55 73 65 72 46 6f 72 6d 34 2e 54 61 67 20 26 20 22 28 49 39 2c 49 31 30 26 4a 31 30 2c 49 31 31 2c 49 31 32 2c 2c 31 2c 39 29 } //01 00  Sheets("Nosto").Range("H9") = "=" & UserForm4.Tag & "(I9,I10&J10,I11,I12,,1,9)
		$a_01_1 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 37 22 29 20 3d 20 22 3d 22 20 26 20 55 73 65 72 46 6f 72 6d 33 2e 54 61 67 20 26 20 22 28 49 31 37 29 } //01 00  Sheets("Nosto").Range("H17") = "=" & UserForm3.Tag & "(I17)
		$a_01_2 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 38 22 29 20 3d 20 22 3d 22 20 26 20 55 73 65 72 46 6f 72 6d 33 2e 54 61 67 20 26 20 22 28 49 31 38 29 } //01 00  Sheets("Nosto").Range("H18") = "=" & UserForm3.Tag & "(I18)
		$a_01_3 = {53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 39 22 29 20 3d 20 22 3d 22 20 26 20 55 73 65 72 46 6f 72 6d 33 2e 54 61 67 20 26 20 22 28 49 31 39 29 } //01 00  Sheets("Nosto").Range("H19") = "=" & UserForm3.Tag & "(I19)
		$a_01_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 68 65 65 74 73 28 22 4e 6f 73 74 6f 22 29 2e 52 61 6e 67 65 28 22 48 31 22 29 } //00 00  Application.Run Sheets("Nosto").Range("H1")
	condition:
		any of ($a_*)
 
}
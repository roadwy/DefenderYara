
rule TrojanDownloader_O97M_Zloader_VA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Zloader.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 4e 6f 74 68 69 6e 67 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 43 61 6c 6c 42 79 4e 61 6d 65 20 90 02 06 2c 20 90 02 06 2c 20 90 02 08 20 3d 20 4e 6f 74 68 69 6e 67 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 00 } //01 00 
		$a_01_1 = {55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 34 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 34 20 26 20 22 30 22 } //01 00  UserForm1.ComboBox4 = UserForm1.ComboBox4 & "0"
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 54 69 6d 65 20 4e 6f 77 20 2b 20 54 69 6d 65 53 65 72 69 61 6c 28 30 2c 20 30 2c 20 32 30 29 2c 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6e 6e 6e 22 } //01 00  Application.OnTime Now + TimeSerial(0, 0, 20), "ThisDocument.nnn"
		$a_01_3 = {2e 73 68 65 65 74 73 28 31 29 } //01 00  .sheets(1)
		$a_03_4 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 49 6e 69 74 69 61 6c 69 7a 65 28 29 90 02 05 43 61 6c 6c 42 79 4e 61 6d 65 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 90 02 05 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 90 02 05 2c 20 56 62 4d 65 74 68 6f 64 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 90 00 } //01 00 
		$a_01_5 = {53 75 62 20 6e 6e 6e 28 29 } //01 00  Sub nnn()
		$a_01_6 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 46 69 6c 65 4e 61 6d 65 3a 3d 55 73 65 72 46 6f 72 6d 32 2e 43 6f 6d 62 6f 42 6f 78 31 2c 20 50 61 73 73 77 6f 72 64 3a 3d 55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 32 29 } //01 00  Workbooks.Open(FileName:=UserForm2.ComboBox1, Password:=UserForm1.ComboBox2)
		$a_01_7 = {2e 52 75 6e 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6e 6e 6e 22 } //00 00  .Run "ThisDocument.nnn"
	condition:
		any of ($a_*)
 
}
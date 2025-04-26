
rule TrojanDownloader_O97M_ZLoader_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 34 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 34 20 26 20 22 30 22 } //1 UserForm1.ComboBox4 = UserForm1.ComboBox4 & "0"
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 54 69 6d 65 20 4e 6f 77 20 2b 20 54 69 6d 65 53 65 72 69 61 6c 28 30 2c 20 30 2c 20 32 30 29 2c 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 } //1 Application.OnTime Now + TimeSerial(0, 0, 20), "ThisDocument
		$a_01_2 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 46 69 6c 65 4e 61 6d 65 3a 3d 55 73 65 72 46 6f 72 6d 32 2e 43 6f 6d 62 6f 42 6f 78 31 2c 20 50 61 73 73 77 6f 72 64 3a 3d 55 73 65 72 46 6f 72 6d 31 2e 43 6f 6d 62 6f 42 6f 78 32 29 } //1 Workbooks.Open(FileName:=UserForm2.ComboBox1, Password:=UserForm1.ComboBox2)
		$a_01_3 = {2e 52 75 6e 20 22 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 22 20 26 20 } //1 .Run "ThisDocument." & 
		$a_01_4 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 70 74 69 6f 6e 73 2e 4d 61 74 63 68 46 75 7a 7a 79 } //1 = Application.Options.MatchFuzzy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
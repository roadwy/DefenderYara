
rule TrojanDropper_Linux_Bartallex_C{
	meta:
		description = "TrojanDropper:Linux/Bartallex.C,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 61 74 68 20 3d 20 77 73 68 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 50 50 44 41 54 41 25 22 29 } //2 Path = wsh.ExpandEnvironmentStrings("%APPDATA%")
		$a_00_1 = {66 73 6f 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 77 69 6e 64 6f 77 73 2e 65 78 65 22 2c 20 32 2c 20 54 72 75 65 29 } //2 fso.OpenTextFile(Path & "\" & "windows.exe", 2, True)
		$a_00_2 = {2e 52 75 6e 20 50 61 74 68 20 26 20 22 5c 77 69 6e 64 6f 77 73 2e 65 78 65 22 } //1 .Run Path & "\windows.exe"
		$a_00_3 = {3d 20 62 61 73 65 36 34 2e 42 61 73 65 36 34 44 65 63 6f 64 65 28 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 31 29 } //1 = base64.Base64Decode(UserForm2.TextBox1)
		$a_00_4 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 .DataType = "bin.base64"
		$a_00_5 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 65 78 65 29 } //1 .WriteLine (exe)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}
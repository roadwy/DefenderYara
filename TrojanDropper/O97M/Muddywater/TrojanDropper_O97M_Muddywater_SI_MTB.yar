
rule TrojanDropper_O97M_Muddywater_SI_MTB{
	meta:
		description = "TrojanDropper:O97M/Muddywater.SI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 69 76 20 3d 20 67 69 76 20 26 20 43 68 72 28 28 56 61 6c 28 4d 69 64 28 69 6e 70 2c 20 63 6f 6e 2c 20 33 29 29 29 29 } //1 giv = giv & Chr((Val(Mid(inp, con, 3))))
		$a_01_1 = {65 70 61 74 68 20 3d 20 4c 65 66 74 28 70 61 74 68 2c 20 4c 65 6e 28 70 61 74 68 29 20 2d 20 34 29 20 26 20 22 2e 65 78 65 } //1 epath = Left(path, Len(path) - 4) & ".exe
		$a_01_2 = {6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 65 70 61 74 68 2c 20 22 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 } //1 objShell.ShellExecute epath, "", "", "open", 1
		$a_01_3 = {70 61 74 68 20 3d 20 22 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 44 6f 63 75 6d 65 6e 74 73 5c 5c 4d 69 63 72 6f 73 6f 66 74 57 6f 72 64 55 73 65 72 2e 6c 6f 67 } //1 path = "C:\\Users\\Public\\Documents\\MicrosoftWordUser.log
		$a_01_4 = {61 70 70 20 3d 20 67 69 76 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 29 } //1 app = give(UserForm1.TextBox1.Text)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
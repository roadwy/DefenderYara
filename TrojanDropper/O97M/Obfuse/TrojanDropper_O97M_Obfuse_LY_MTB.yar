
rule TrojanDropper_O97M_Obfuse_LY_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.LY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //1 = ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & ".js"
		$a_01_1 = {4d 73 67 42 6f 78 20 22 48 69 22 } //1 MsgBox "Hi"
		$a_01_2 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 } //1 = UserForm2.TextBox3.Value
		$a_01_3 = {2e 57 72 69 74 65 20 67 65 74 5f 54 45 58 54 5f 44 41 54 41 } //1 .Write get_TEXT_DATA
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 73 74 61 72 74 57 61 72 46 69 6c 65 52 75 6e } //1 .ShellExecute startWarFileRun
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
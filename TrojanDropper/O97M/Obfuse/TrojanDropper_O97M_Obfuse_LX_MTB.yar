
rule TrojanDropper_O97M_Obfuse_LX_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.LX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //1 = ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & ".js"
		$a_01_1 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //1 = UserForm1.TextBox1.Value
		$a_01_2 = {49 66 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 46 6f 72 6d 46 69 65 6c 64 73 28 22 54 65 78 74 31 22 29 2e 52 65 73 75 6c 74 20 3d 20 22 22 20 54 68 65 6e } //1 If ActiveDocument.FormFields("Text1").Result = "" Then
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 65 6e 64 66 69 6c 65 72 75 6e 32 } //1 .ShellExecute endfilerun2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
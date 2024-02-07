
rule TrojanDropper_O97M_Obfuse_LN_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.LN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //01 00  = ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & ".js"
		$a_01_1 = {2e 54 65 78 74 20 3d 20 50 75 6e 63 4d 61 72 6b 20 26 20 22 20 20 20 22 } //01 00  .Text = PuncMark & "   "
		$a_01_2 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 } //01 00  UserForm1.TextBox1.Text
		$a_01_3 = {4d 73 67 42 6f 78 20 22 48 69 22 } //01 00  MsgBox "Hi"
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 72 75 6e 46 69 6c 65 } //00 00  .ShellExecute runFile
	condition:
		any of ($a_*)
 
}
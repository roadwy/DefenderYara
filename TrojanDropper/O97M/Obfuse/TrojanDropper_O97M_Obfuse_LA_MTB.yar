
rule TrojanDropper_O97M_Obfuse_LA_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.LA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 2e 6a 73 65 22 } //01 00  ".jse"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 43 68 72 28 39 32 29 20 26 } //01 00  = Environ("USERPROFILE") & Chr(92) &
		$a_01_2 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //01 00  = UserForm1.TextBox1.Value
		$a_01_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 2e 43 6f 75 6e 74 } //01 00  ActiveDocument.Shapes.Count
		$a_01_4 = {3d 20 4e 75 6c 6c } //01 00  = Null
		$a_01_5 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 28 73 74 61 72 74 29 } //00 00  .ShellExecute (start)
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Obfuse_MJ_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.MJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //1 & Chr(92) & Rnd & ".js"
		$a_03_1 = {54 65 78 74 3a 3d 22 3d 20 22 20 2b 20 [0-16] 20 2b 20 22 20 5c 2a 20 43 61 72 64 54 65 78 74 22 2c 20 5f } //1
		$a_01_2 = {6a 73 54 65 78 74 34 54 65 78 74 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 } //1 jsText4Text = UserForm1.TextBox1.Text
		$a_01_3 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 54 65 78 74 20 54 65 78 74 3a } //1 Selection.TypeText Text:
		$a_03_4 = {4f 70 65 6e 20 [0-24] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_5 = {57 73 68 53 63 72 69 70 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 WshScript.ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
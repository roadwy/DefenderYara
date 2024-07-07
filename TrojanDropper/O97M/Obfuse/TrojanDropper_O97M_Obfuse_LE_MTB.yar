
rule TrojanDropper_O97M_Obfuse_LE_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.LE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //1 & Chr(92) & Rnd & ".js"
		$a_03_1 = {54 65 78 74 3a 3d 22 3d 20 22 20 2b 20 90 02 14 20 2b 20 22 20 5c 2a 20 43 61 72 64 54 65 78 74 22 2c 20 5f 90 00 } //1
		$a_01_2 = {22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 } //1 "MyDocuments"
		$a_01_3 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //1 UserForm1.TextBox1.Value
		$a_01_4 = {4d 73 67 42 6f 78 28 22 54 68 65 72 65 20 77 65 72 65 20 22 20 26 20 54 72 69 6d 28 53 74 72 28 } //1 MsgBox("There were " & Trim(Str(
		$a_03_5 = {4f 70 65 6e 20 90 02 25 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
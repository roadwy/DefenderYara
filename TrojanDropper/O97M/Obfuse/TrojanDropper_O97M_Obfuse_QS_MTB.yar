
rule TrojanDropper_O97M_Obfuse_QS_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.QS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 73 74 72 2e 49 74 65 6d 28 31 29 29 20 26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 22 } //1 = Environ(str.Item(1)) & Chr(92) & Rnd & ".jse"
		$a_01_1 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 2e 43 61 70 74 69 6f 6e } //1 UserForm1.Text.Caption
		$a_01_2 = {3d 20 4f 53 46 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 74 68 69 73 5f 69 73 5f 79 6f 75 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 = OSF.CreateTextFile(this_is_you, True, True)
		$a_01_3 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 74 68 69 73 5f 69 73 5f 79 6f 75 2c 20 22 22 2c 20 22 43 22 20 26 20 22 3a 5c 22 2c 20 22 6f 70 65 6e 22 2c 20 31 } //1 .ShellExecute this_is_you, "", "C" & ":\", "open", 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
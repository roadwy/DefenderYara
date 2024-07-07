
rule TrojanDropper_O97M_Obfuse_PE_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 22 } //1 & Chr(92) & Rnd & ".js"
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 Environ("USERPROFILE")
		$a_01_2 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 73 61 76 65 66 69 6c 65 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 .CreateTextFile(savefile, True, True)
		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
		$a_01_4 = {2e 43 72 65 61 74 65 28 72 75 6e 66 69 6c 65 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1 .Create(runfile, Null, Null, intProcessID)
		$a_01_5 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //1 = UserForm1.TextBox1.Value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
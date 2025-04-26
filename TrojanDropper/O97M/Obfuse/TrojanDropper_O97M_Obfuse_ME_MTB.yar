
rule TrojanDropper_O97M_Obfuse_ME_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.ME!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 6a 73 65 22 } //1 = ".jse"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 = Environ("USERPROFILE")
		$a_01_2 = {3d 20 43 68 72 28 39 32 29 } //1 = Chr(92)
		$a_01_3 = {3d 20 52 6e 64 } //1 = Rnd
		$a_01_4 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //1 = UserForm1.TextBox1.Value
		$a_01_5 = {3d 20 41 73 63 28 4d 69 64 28 73 44 6f 63 2c } //1 = Asc(Mid(sDoc,
		$a_01_6 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 54 65 78 74 20 54 65 78 74 3a 3d 73 54 65 6d 70 } //1 Selection.TypeText Text:=sTemp
		$a_01_7 = {2e 57 72 69 74 65 20 74 65 78 74 77 72 69 74 65 } //1 .Write textwrite
		$a_01_8 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
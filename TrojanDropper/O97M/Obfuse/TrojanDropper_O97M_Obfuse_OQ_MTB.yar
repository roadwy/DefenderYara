
rule TrojanDropper_O97M_Obfuse_OQ_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.OQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 6e 64 20 26 20 22 2e 22 20 26 20 65 78 65 73 68 69 6f 6e 20 26 20 22 73 65 22 } //1 = Rnd & "." & exeshion & "se"
		$a_01_1 = {26 20 72 65 74 75 72 6e 53 6c 61 73 68 28 39 32 29 20 26 20 6e 61 6d 65 4f 66 46 69 6c 65 28 22 6a 22 29 } //1 & returnSlash(92) & nameOfFile("j")
		$a_01_2 = {28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 ("USERPROFILE")
		$a_01_3 = {45 6e 76 69 72 6f 6e 28 } //1 Environ(
		$a_01_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 66 69 6c 65 46 72 6f 53 61 76 65 4a 73 4d 61 63 72 6f 73 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 .CreateTextFile(fileFroSaveJsMacros, True, True)
		$a_01_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 = CreateObject("Shell.Application")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
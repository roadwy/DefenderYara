
rule TrojanDropper_O97M_Obfuse_NU_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.NU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {22 2e 6a 73 65 22 } //1 ".jse"
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 Environ("USERPROFILE")
		$a_01_2 = {43 68 72 28 39 32 29 } //1 Chr(92)
		$a_01_3 = {6a 73 54 65 78 74 34 54 65 78 74 } //1 jsText4Text
		$a_01_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 .ShellExecute
		$a_01_5 = {3d 20 64 6f 63 54 68 69 73 2e } //1 = docThis.
		$a_01_6 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 6e 61 6d 65 4f 46 46 49 4c 45 53 4f 46 52 53 41 56 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1 .CreateTextFile(nameOFFILESOFRSAV, True, True)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
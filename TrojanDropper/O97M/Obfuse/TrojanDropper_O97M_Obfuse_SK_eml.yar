
rule TrojanDropper_O97M_Obfuse_SK_eml{
	meta:
		description = "TrojanDropper:O97M/Obfuse.SK!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 28 6e 61 6d 65 72 75 6e 29 } //1 .ShellExecute (namerun)
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 43 68 72 28 39 32 29 } //1 = Environ("USERPROFILE") & Chr(92)
		$a_01_2 = {3d 20 46 6f 6c 64 65 72 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 22 } //1 = Folder & Rnd & ".jse"
		$a_01_3 = {53 65 6c 65 63 74 69 6f 6e 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c } //1 Selection.Find.Execute Replace:=wdReplaceAll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
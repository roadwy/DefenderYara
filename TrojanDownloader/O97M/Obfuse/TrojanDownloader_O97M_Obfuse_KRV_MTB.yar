
rule TrojanDownloader_O97M_Obfuse_KRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_1 = {2e 52 65 67 57 72 69 74 65 20 73 63 72 65 65 6e 56 61 6c 75 65 43 6f 75 6e 74 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 } //1 .RegWrite screenValueCount, 1, "REG_DWORD"
		$a_01_2 = {74 65 78 74 62 6f 78 50 72 6f 63 65 64 75 72 65 43 6f 6c 6c 65 63 74 69 6f 6e 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 textboxProcedureCollection = CreateObject("word.application")
		$a_01_3 = {20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 } //1  = UserForm1.TextBox1
		$a_01_4 = {67 6c 6f 62 61 6c 4d 65 6d 6f 72 79 20 3d 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 } //1 globalMemory = "\Word\Security\AccessVBOM"
		$a_01_5 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a 62 75 66 56 61 72 69 61 62 6c 65 49 6e 64 65 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule TrojanDownloader_O97M_Obfuse_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 22 50 72 6f 6a 65 63 74 2e 4d 61 63 72 6f 42 6c 65 2e 41 75 74 6f 4f 70 65 6e 22 } //1 .VB_ProcData.VB_Invoke_Func = "Project.MacroBle.AutoOpen"
		$a_00_1 = {2e 53 61 76 65 41 73 20 28 47 65 74 50 61 74 68 24 20 2b 20 22 4e 4f 52 4d 41 4c 31 2e 44 4f 54 22 29 } //1 .SaveAs (GetPath$ + "NORMAL1.DOT")
		$a_00_2 = {27 4d 73 67 42 6f 78 20 22 46 75 63 6b 20 75 70 20 21 } //1 'MsgBox "Fuck up !
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_02_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 ?? ?? ?? ?? ?? 20 2b 20 22 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1
		$a_00_1 = {53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c } //1 String = "c:\programdata\
		$a_02_2 = {28 30 29 20 2b 20 22 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? 2e 74 78 74 22 2c 20 22 77 73 22 } //6
		$a_02_3 = {28 30 29 20 2b 20 22 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? 2e 70 64 66 22 2c 20 22 77 73 22 } //6
		$a_02_4 = {53 70 6c 69 74 28 ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? 29 } //1
		$a_00_5 = {2e 4f 70 65 6e 20 22 47 45 54 } //1 .Open "GET
		$a_00_6 = {2e 72 65 73 70 6f 6e 73 65 62 6f 64 79 } //1 .responsebody
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*6+(#a_02_3  & 1)*6+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=11
 
}

rule TrojanDropper_O97M_Obfuse_EW_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.EW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 63 6f 75 6e 74 65 72 } //1 MsgBox counter
		$a_00_1 = {63 6f 75 6e 74 65 72 20 3d 20 30 } //1 counter = 0
		$a_00_2 = {62 75 66 66 28 63 6f 75 6e 74 65 72 29 20 3d 20 41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 } //1 buff(counter) = ActiveSheet.Cells
		$a_00_3 = {70 75 74 46 69 6c 65 20 3d 20 46 72 65 65 46 69 6c 65 } //1 putFile = FreeFile
		$a_00_4 = {53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 6a 70 67 22 29 } //1 Shell ("cmd.exe /c start cplusconsole.jpg")
		$a_00_5 = {4f 70 65 6e 20 22 43 3a 5c 76 62 5c 63 70 6c 75 73 63 6f 6e 73 6f 6c 65 2e 6a 70 67 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 70 75 74 46 69 6c 65 } //1 Open "C:\vb\cplusconsole.jpg" For Binary Access Write As putFile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
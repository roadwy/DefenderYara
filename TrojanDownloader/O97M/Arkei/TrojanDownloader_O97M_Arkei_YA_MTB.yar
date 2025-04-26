
rule TrojanDownloader_O97M_Arkei_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Arkei.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecute Lib "shell32.dll" Alias "ShellExecuteA
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 53 63 72 5f 68 44 43 2c 20 22 4f 70 65 6e 22 2c 20 44 6f 63 4e 61 6d 65 2c 20 22 22 2c 20 22 43 3a 5c } //1 ShellExecute(Scr_hDC, "Open", DocName, "", "C:\
		$a_01_2 = {73 74 61 72 74 44 6f 63 28 73 61 76 65 46 6f 6c 64 65 72 20 26 20 22 5c 47 65 72 74 61 2e 76 62 73 22 29 } //1 startDoc(saveFolder & "\Gerta.vbs")
		$a_01_3 = {73 61 76 65 46 6f 6c 64 65 72 20 26 20 22 5c 47 65 72 74 61 2e 63 6d 64 22 } //1 saveFolder & "\Gerta.cmd"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}

rule TrojanDownloader_O97M_Donoff_PA_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //2 WScript.Shell
		$a_01_1 = {6d 6f 64 4a 6f 72 64 61 6e 45 78 63 65 6c 2e 53 61 76 65 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 } //2 modJordanExcel.Save ActiveDocument
		$a_03_2 = {63 3a 5c 41 74 74 61 [0-02] 5c 6c 64 72 2e 65 78 65 27 } //2
		$a_03_3 = {68 74 74 70 [0-01] 3a 2f 2f [0-03] 2e [0-03] 2e [0-03] 2e [0-03] 2f 6c 64 72 2e 65 78 65 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}
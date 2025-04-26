
rule TrojanDownloader_O97M_Powdow_RVAY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 73 63 72 69 70 74 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 74 65 78 74 66 69 6c 65 2e 6a 73 22 63 61 6c 6c 73 68 65 6c 6c 28 61 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 } //1 wscriptc:\users\public\textfile.js"callshell(a,vbnormalfocus)
		$a_01_1 = {3d 77 6f 72 6b 73 68 65 65 74 73 28 22 62 6c 61 6e 6b 65 64 22 29 2e 72 61 6e 67 65 28 22 74 6f 31 30 32 39 22 29 70 72 69 6e 74 23 74 65 78 74 66 69 6c 65 2c 79 6f 75 74 75 62 65 } //1 =worksheets("blanked").range("to1029")print#textfile,youtube
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 6d 6f 74 6f 72 66 69 6c 65 65 6e 64 73 75 62 } //1 workbook_open()motorfileendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
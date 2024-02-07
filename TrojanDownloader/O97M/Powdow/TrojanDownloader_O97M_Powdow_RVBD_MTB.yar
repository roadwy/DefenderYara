
rule TrojanDownloader_O97M_Powdow_RVBD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 22 } //01 00  "c:\users\public\update.js"
		$a_01_1 = {77 6f 72 6b 73 68 65 65 74 73 28 22 6c 6f 6c 22 29 2e 72 61 6e 67 65 28 22 6c 35 22 29 6f 70 65 6e 73 66 69 6c 65 66 6f 72 6f 75 74 70 75 74 61 73 23 31 70 72 69 6e 74 23 31 2c 79 6f 75 74 75 62 65 } //01 00  worksheets("lol").range("l5")opensfileforoutputas#1print#1,youtube
		$a_01_2 = {77 73 63 72 69 70 74 22 2b 73 66 69 6c 65 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 2e 70 72 69 6e 74 } //01 00  wscript"+sfile:::::::::::debug.print
		$a_01_3 = {63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 21 28 61 73 73 73 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 } //01 00  callvba.shell!(asss,vbnormalfocus)
		$a_01_4 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //00 00  workbook_open()
	condition:
		any of ($a_*)
 
}
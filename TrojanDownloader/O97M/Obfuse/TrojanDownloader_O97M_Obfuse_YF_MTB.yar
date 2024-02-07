
rule TrojanDownloader_O97M_Obfuse_YF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 30 2e 31 32 35 2e 36 35 2e 33 33 2f 61 73 79 6e 63 2e 65 78 65 } //01 00  http://40.125.65.33/async.exe
		$a_01_1 = {61 73 79 6e 63 2e 65 78 65 22 2c 20 32 20 27 20 31 } //01 00  async.exe", 2 ' 1
		$a_01_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 61 73 79 6e 63 2e 65 78 65 } //00 00  ActiveWorkbook.Path & "\async.exe
	condition:
		any of ($a_*)
 
}
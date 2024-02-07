
rule TrojanDownloader_O97M_Endoc_VS_MSR{
	meta:
		description = "TrojanDownloader:O97M/Endoc.VS!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6d 67 73 72 63 20 3d 20 22 68 74 74 70 3a 2f 2f 38 30 2e 37 38 2e 32 35 2e 32 32 33 2f 77 61 6c 74 65 72 2e 70 6e 67 22 } //01 00  imgsrc = "http://80.78.25.223/walter.png"
		$a_00_1 = {62 61 74 63 68 46 69 6c 65 20 3d 20 22 43 3a 5c 54 65 6d 70 5c 77 61 6c 74 65 72 2e 62 61 74 22 } //00 00  batchFile = "C:\Temp\walter.bat"
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_O97M_Donoff_SM_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 65 67 61 76 75 2e 63 6f 6d 2f 37 32 38 30 2d 32 38 31 32 2d 33 33 33 32 2e 64 6c 6c } //1 https://tegavu.com/7280-2812-3332.dll
		$a_01_1 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 RLDownloadToFileA
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_SM_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SM!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 74 65 20 3d 20 47 65 74 54 65 6d 70 50 61 74 68 41 28 35 31 32 2c 20 73 29 } //1 inte = GetTempPathA(512, s)
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {75 20 3d 20 53 68 65 65 74 73 28 22 53 68 65 65 74 31 22 29 2e 52 61 6e 67 65 28 22 43 34 22 29 } //1 u = Sheets("Sheet1").Range("C4")
		$a_01_3 = {62 20 3d 20 53 68 65 65 74 73 28 22 53 68 65 65 74 31 22 29 2e 52 61 6e 67 65 28 22 43 31 30 22 29 } //1 b = Sheets("Sheet1").Range("C10")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
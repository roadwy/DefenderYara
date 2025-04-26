
rule TrojanDownloader_O97M_Donoff_RU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 = CreateObject("wscript.shell")
		$a_01_1 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d 20 } //1 Environment("process").Item("param1") = 
		$a_01_2 = {45 36 73 69 7a 58 38 5a 2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } //1 E6sizX8Z.run "cmd /c call %param1%", 2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_RU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 } //1 = "powershell -noP -sta -w 1 -enc
		$a_03_1 = {20 2b 20 22 41 70 41 48 77 41 53 51 42 46 41 46 67 41 22 0d 0a [0-1f] 53 65 74 20 [0-07] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a [0-1f] 90 1b 01 2e 52 75 6e 20 28 76 58 6f 79 45 58 4e 74 58 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
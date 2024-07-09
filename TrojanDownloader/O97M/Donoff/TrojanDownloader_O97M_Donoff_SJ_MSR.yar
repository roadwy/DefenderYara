
rule TrojanDownloader_O97M_Donoff_SJ_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SJ!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 } //1 = ActiveDocument.Range
		$a_01_1 = {22 2e 6a 73 65 22 } //1 ".jse"
		$a_01_2 = {52 61 6e 64 6f 6d 69 7a 65 } //1 Randomize
		$a_01_3 = {52 6e 64 20 26 } //1 Rnd &
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_03_5 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-19] 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //1
		$a_01_6 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_01_7 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 .ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
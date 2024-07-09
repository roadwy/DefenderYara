
rule TrojanDownloader_O97M_Powdow_SHS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SHS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 } //1 "shell32.dll" Alias "ShellExecuteA" (
		$a_01_1 = {28 31 2c 20 53 74 72 52 65 76 65 72 73 65 28 22 6e 65 70 4f 22 29 2c 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 22 29 2c 20 53 74 72 52 65 76 65 72 73 65 28 22 20 73 62 76 2e 65 6e 6f 44 20 65 78 65 2e 72 65 72 6f 6c 70 78 65 3b 73 62 76 2e 65 6e 6f 44 20 6f 2d 20 73 62 76 2e 73 75 72 69 76 5f 6b 72 61 64 2f 6c 61 70 79 61 70 2f 31 39 31 2e 38 31 31 2e 30 35 32 2e 36 31 32 20 74 65 67 77 20 6e 65 64 64 69 48 20 65 6c 79 74 53 77 6f 64 6e 69 57 2d 20 22 29 } //1 (1, StrReverse("nepO"), StrReverse("exe.llehsrewop"), StrReverse(" sbv.enoD exe.rerolpxe;sbv.enoD o- sbv.suriv_krad/lapyap/191.811.052.612 tegw neddiH elytSwodniW- ")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_SHS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SHS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-1f] 28 22 [0-2f] 22 29 20 26 20 [0-1f] 28 22 [0-2f] 22 29 29 } //1
		$a_01_1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 22 5c 63 79 6d 5f 31 36 30 30 31 33 38 30 34 33 30 42 44 38 34 42 32 34 2e 65 78 65 22 } //1 .ExpandEnvironmentStrings("%TEMP%") & "\cym_16001380430BD84B24.exe"
		$a_01_2 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 4e 61 6d 65 64 29 } //1 objShell.Run (Named)
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-1f] 28 22 [0-2f] 22 29 20 26 20 [0-1f] 28 22 [0-2f] 22 29 29 } //1
		$a_03_4 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 [0-1f] 28 22 [0-2f] 22 29 29 } //1
		$a_03_5 = {45 4c 2e 44 61 74 61 54 79 70 65 20 3d 20 [0-1f] 28 22 [0-2f] 22 29 20 26 20 [0-1f] 28 22 [0-2f] 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
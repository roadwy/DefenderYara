
rule TrojanDownloader_O97M_Donoff_DRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 26 20 22 69 6e 76 6f 6b 65 2d 77 65 62 72 65 71 75 65 73 74 } //1 cmd & "invoke-webrequest
		$a_03_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6f 78 30 78 6f 2f 6f 78 30 78 6f 2e 67 69 74 68 75 62 2e 69 6f 2f 72 61 77 2f 6d 61 73 74 65 72 2f 61 72 74 69 66 61 63 74 2f 63 61 6c 63 2e 65 78 65 90 0a 4c 00 63 6d 64 20 26 20 22 68 74 74 70 73 3a 2f 2f } //1
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_3 = {2d 6f 75 74 66 69 6c 65 20 25 74 6d 70 25 2f 63 61 6c 63 2e 65 78 65 } //1 -outfile %tmp%/calc.exe
		$a_01_4 = {73 68 2e 52 75 6e 20 63 6d 64 2c 20 30 2c 20 46 61 6c 73 65 } //1 sh.Run cmd, 0, False
		$a_01_5 = {63 6d 64 20 26 20 22 25 74 6d 70 25 2f 63 61 6c 63 2e 65 78 65 22 } //1 cmd & "%tmp%/calc.exe"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
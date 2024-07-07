
rule TrojanDownloader_O97M_Donoff_STSV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STSV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {27 68 74 74 70 73 3a 2f 2f 69 6d 61 67 69 6e 65 2d 77 6f 72 6c 64 2e 63 6f 6d 2f 27 2b 24 90 02 1f 29 90 00 } //1
		$a_01_1 = {22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 70 72 6e 63 6e 66 67 2e 74 78 74 22 } //1 "C:\ProgramData\prncnfg.txt"
		$a_01_2 = {43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 74 65 6d 70 20 26 20 22 5c 67 61 74 68 65 72 4e 65 74 77 6f 72 6b 49 6e 66 6f 2e 76 22 20 26 20 43 68 72 28 39 38 29 20 26 20 22 73 22 29 } //1 CreateTextFile(temp & "\gatherNetworkInfo.v" & Chr(98) & "s")
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
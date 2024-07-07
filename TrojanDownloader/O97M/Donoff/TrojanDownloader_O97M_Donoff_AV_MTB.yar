
rule TrojanDownloader_O97M_Donoff_AV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 63 6c 6f 73 65 28 29 } //1 autoclose()
		$a_01_1 = {52 45 74 61 73 20 3d 20 45 6e 76 69 72 6f 6e 28 54 65 72 69 6f 6c 2e 43 61 70 74 69 6f 6e 29 } //1 REtas = Environ(Teriol.Caption)
		$a_01_2 = {54 32 2e 54 31 } //1 T2.T1
		$a_01_3 = {53 68 65 6c 6c 20 22 63 6d 64 2e 65 78 65 20 2f 63 22 20 26 20 52 45 74 61 73 20 26 20 54 65 72 69 6f 6c 2e 54 61 67 2c 20 30 } //1 Shell "cmd.exe /c" & REtas & Teriol.Tag, 0
		$a_01_4 = {48 65 72 74 69 20 3d 20 52 45 74 61 73 20 26 20 54 65 72 69 6f 6c 2e 54 61 67 } //1 Herti = REtas & Teriol.Tag
		$a_01_5 = {4f 70 65 6e 20 48 65 72 74 69 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1 Open Herti For Output As #1
		$a_01_6 = {50 72 69 6e 74 20 23 31 2c 20 54 65 72 69 6f 6c 2e 54 65 72 69 6f 70 65 } //1 Print #1, Teriol.Teriope
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
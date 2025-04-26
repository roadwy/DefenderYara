
rule TrojanDownloader_O97M_RevengeRAT_SE_MTB{
	meta:
		description = "TrojanDownloader:O97M/RevengeRAT.SE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 2f [0-08] 2f 63 6d 6c 55 58 72 45 78 2e } //1
		$a_03_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 [0-64] 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e [0-03] 22 2c 20 30 2c 20 30 } //1
		$a_01_2 = {65 78 65 22 22 20 2f 63 20 70 69 } //1 exe"" /c pi
		$a_01_3 = {6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 31 30 } //1 ng 127.0.0.1 -n 10
		$a_01_4 = {3e 20 6e 75 6c 20 26 20 73 74 61 72 74 20 43 } //1 > nul & start C
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
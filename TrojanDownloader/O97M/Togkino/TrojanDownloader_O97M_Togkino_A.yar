
rule TrojanDownloader_O97M_Togkino_A{
	meta:
		description = "TrojanDownloader:O97M/Togkino.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 54 6f 20 6e 69 6b 6f 33 } //1 GoTo niko3
		$a_03_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 22 68 74 74 70 3a 2f 2f [0-15] 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 [0-09] 2e 65 78 65 22 2c 20 30 2c 20 30 } //1
		$a_01_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 } //1 Shell Environ("TEMP") &
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
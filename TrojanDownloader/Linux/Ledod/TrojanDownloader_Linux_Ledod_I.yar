
rule TrojanDownloader_Linux_Ledod_I{
	meta:
		description = "TrojanDownloader:Linux/Ledod.I,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6c 61 20 50 75 74 6f } //1 Hola Puto
		$a_03_1 = {4d 6f 72 64 65 64 6f 72 20 30 2c 20 22 [0-60] 2e (65 78 65|73 63 72) 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c [0-08] 2e 65 78 65 22 2c 20 30 2c 20 30 } //1
		$a_03_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c [0-08] 2e 65 78 65 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
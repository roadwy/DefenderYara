
rule TrojanDownloader_Linux_Ledod_E{
	meta:
		description = "TrojanDownloader:Linux/Ledod.E,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 01 0b 2e 72 45 61 64 79 53 54 61 54 65 20 3c 3e 20 34 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4c 6f 6f 70 0d 0a 90 01 0b 20 3d 20 90 01 0b 2e 72 65 73 50 6f 6e 73 65 42 6f 44 79 90 00 } //1
		$a_03_1 = {53 68 65 6c 6c 28 90 01 0b 2c 20 31 29 90 02 50 22 68 74 74 70 3a 2f 2f 90 02 30 2e 65 78 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 90 01 0b 2e 73 63 72 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
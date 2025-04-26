
rule TrojanDownloader_Linux_Adobdocro_A{
	meta:
		description = "TrojanDownloader:Linux/Adobdocro.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 [0-85] 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f [0-35] 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1
		$a_02_1 = {2e 54 79 70 65 20 3d 20 31 [0-10] 2e 4f 70 65 6e [0-10] 2e 77 72 69 74 65 [0-35] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 [0-35] 2e 73 61 76 65 74 6f 66 69 6c 65 [0-35] 2e 63 6f 6d 22 2c [0-05] 32 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
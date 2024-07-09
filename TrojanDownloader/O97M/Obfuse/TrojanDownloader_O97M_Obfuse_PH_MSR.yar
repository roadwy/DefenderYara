
rule TrojanDownloader_O97M_Obfuse_PH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 76 50 61 74 68 20 26 20 22 5c [0-20] 2e 74 78 74 22 29 } //1
		$a_03_1 = {43 61 6c 6c 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e [0-10] 6d 67 6d 74 73 3a 72 6f [0-10] 6f 74 5c 63 [0-10] 69 6d 76 32 3a 57 69 [0-10] 6e 33 32 5f 50 [0-10] 72 6f [0-10] 63 65 73 73 } //1
		$a_01_2 = {6e 65 2d 20 6e 65 64 64 69 68 20 65 6c 79 74 73 77 6f 64 6e 69 77 2d 20 6c 6c 65 68 73 72 65 77 6f 70 } //1 ne- neddih elytswodniw- llehsrewop
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule TrojanDownloader_O97M_Obfuse_DR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_03_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-60] 20 2b 20 [0-60] 29 2e 20 5f } //2
		$a_03_1 = {43 72 65 61 74 65 ?? 20 5f } //1
		$a_01_2 = {22 77 69 6e 6d 22 20 2b 20 22 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 20 2b } //1 "winm" + "gmts:Win32_Process") +
		$a_01_3 = {22 77 69 6e 6d 22 20 2b 20 22 67 6d 74 73 3a 57 69 6e 33 22 20 2b 20 22 32 5f 50 72 6f 63 65 73 73 22 29 20 2b } //1 "winm" + "gmts:Win3" + "2_Process") +
		$a_03_4 = {22 77 69 6e 6d 22 20 2b 20 [0-10] 20 2b 20 22 67 6d 74 73 3a 57 69 6e 33 22 20 2b 20 22 32 5f 50 72 6f 63 22 20 2b 20 22 65 73 73 22 29 20 2b 20 } //1
		$a_03_5 = {22 77 69 6e 6d 22 20 2b 20 [0-10] 20 2b 20 22 67 6d 74 73 22 20 2b 20 22 3a 57 69 6e 33 22 20 2b 20 22 32 5f 50 72 6f 63 22 20 2b 20 22 65 73 73 22 29 20 2b 20 } //1
		$a_03_6 = {2b 20 22 32 5f 50 72 6f 63 22 20 2b 20 22 65 73 73 22 29 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20 } //1
		$a_03_7 = {2b 20 22 32 5f 22 20 2b 20 22 50 72 6f 63 22 20 2b 20 22 65 73 73 22 29 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20 } //1
		$a_03_8 = {22 67 6d 74 73 3a 57 69 6e 33 22 20 2b 20 22 32 5f 50 72 6f 63 22 20 2b 20 22 65 73 73 22 29 20 2b 20 [0-10] 20 2b 20 } //1
		$a_01_9 = {22 67 6d 74 73 22 20 2b 20 22 3a 57 69 6e 33 22 20 5f } //1 "gmts" + ":Win3" _
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}
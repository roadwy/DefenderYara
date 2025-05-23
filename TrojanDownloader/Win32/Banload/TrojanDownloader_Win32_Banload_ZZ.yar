
rule TrojanDownloader_Win32_Banload_ZZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 2c 6f 75 20 6f } //1
		$a_00_1 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00 00 00 00 46 61 6c 68 61 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 20 6f 75 20 6f } //1
		$a_02_2 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 [0-30] 10 00 00 00 55 61 63 44 69 73 61 62 6c 65 } //1
		$a_02_3 = {69 65 78 70 6c 6f 72 65 72 [0-30] 70 6c 61 6e 65 74 68 6f 74 } //1
		$a_02_4 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 [0-30] 2d 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 } //1
		$a_02_5 = {43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e [0-30] 69 65 78 70 6c 6f 72 65 72 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=3
 
}

rule TrojanDownloader_O97M_Obfuse_PG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 6a 4b 6c 53 68 6c 53 74 71 42 4c 6f 59 4b 6e 4c 66 71 4a 63 4e 71 55 4a 59 5a 75 6c 74 67 57 } //1 hjKlShlStqBLoYKnLfqJcNqUJYZultgW
		$a_00_1 = {47 65 74 4f 62 6a 65 63 74 28 22 57 69 4e 6d 47 6d 54 73 3a 7b 49 6d 50 65 52 73 4f 6e 41 74 49 6f 4e 6c 45 76 45 6c 3d 49 6d 50 65 52 73 4f 6e 41 74 45 7d 21 5c 5c 2e 5c 52 6f 4f 74 5c 43 69 4d 76 32 } //1 GetObject("WiNmGmTs:{ImPeRsOnAtIoNlEvEl=ImPeRsOnAtE}!\\.\RoOt\CiMv2
		$a_00_2 = {2e 47 65 74 28 22 77 49 6e 33 32 5f 70 52 6f 43 65 53 73 } //1 .Get("wIn32_pRoCeSs
		$a_03_3 = {22 20 68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 [0-14] 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 67 22 20 2b 20 22 72 22 20 2b 20 22 6f 22 20 2b 20 22 75 22 20 2b 20 22 70 22 20 2b 20 22 73 22 20 2b 20 22 2e 22 20 2b 20 22 75 22 20 2b 20 22 73 22 20 2b 20 22 2e 22 20 2b 20 22 74 22 20 2b 20 22 6f 22 20 2b 20 22 3a 22 20 2b 20 22 36 22 20 2b 20 22 39 22 20 2b 20 22 2f 22 20 2b 20 22 30 22 20 2b 20 22 33 22 20 2b 20 22 2e 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 6d } //1
		$a_00_4 = {22 6d 22 20 2b 20 22 53 22 20 2b 20 22 68 22 20 2b 20 22 54 22 20 2b 20 22 61 22 } //1 "m" + "S" + "h" + "T" + "a"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
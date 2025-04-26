
rule TrojanDownloader_O97M_Obfuse_DG{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DG,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 22 20 2b 20 22 74 73 3a 57 69 6e 22 20 2b 20 22 33 32 5f 50 72 6f 63 65 22 20 2b 20 22 73 73 53 74 61 72 74 75 70 22 29 } //1 = GetObject("winmgm" + "ts:Win" + "32_Proce" + "ssStartup")
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 22 20 2b 20 22 6d 74 73 3a 57 69 22 20 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 2e 43 72 65 61 74 65 } //1 GetObject("winmg" + "mts:Wi" + "n32_Process").Create
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
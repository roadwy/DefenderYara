
rule TrojanDownloader_O97M_Obfuse_RVP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 54 65 73 74 45 78 70 6c 6f 69 74 2e 65 78 65 22 } //1 Environ("TMP") & "\TestExploit.exe"
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 6c 6c 74 62 70 73 78 67 6b 71 70 63 28 22 35 37 35 33 36 33 37 32 36 39 37 30 37 34 32 65 35 33 22 29 20 26 20 6c 6c 74 62 70 73 78 67 6b 71 70 63 28 22 36 38 36 35 36 63 36 63 22 29 } //1 CreateObject(lltbpsxgkqpc("575363726970742e53") & lltbpsxgkqpc("68656c6c")
		$a_00_2 = {77 71 70 72 68 6e 71 79 6b 74 67 6b 66 6e 69 6c 67 75 79 7a 2e 52 75 6e 20 73 74 72 46 69 6c 65 6e 61 6d 65 } //1 wqprhnqyktgkfnilguyz.Run strFilename
		$a_00_3 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 78 7a 6e 6c 7a 75 70 66 73 7a 6d 67 2c 20 63 63 64 6f 64 78 67 76 6e 67 79 6c 2c 20 32 29 29 } //1 Chr$(Val("&H" & Mid$(xznlzupfszmg, ccdodxgvngyl, 2))
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
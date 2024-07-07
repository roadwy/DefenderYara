
rule TrojanDownloader_O97M_Powdow_RVAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 20 5f 0d 0a 28 70 69 6e 67 73 29 } //1
		$a_01_1 = {4b 41 52 54 49 43 20 3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 KARTIC = "://www.bitly.com/"
		$a_03_2 = {4c 47 20 3d 20 22 90 02 01 68 74 74 70 73 22 90 00 } //1
		$a_01_3 = {54 20 3d 20 54 41 65 63 20 2b 20 54 59 69 6e 67 } //1 T = TAec + TYing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_RVAL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 20 49 44 30 67 54 6d 56 33 4c 55 39 69 61 6d 56 6a 64 43 42 54 65 58 4e 30 5a 57 30 75 54 6d 56 30 4c 6c 4e 76 59 32 74 6c 64 48 4d 75 56 45 4e 51 51 32 78 70 5a 57 35 30 4b 43 63 78 4f 54 49 75 4d 54 59 34 4c 6a 51 35 4c 6a 63 32 4a 79 77 34 4d 44 67 79 4b 54 73 67 50 53 41 75 52 32 56 30 55 33 52 79 5a 57 46 74 4b 43 6b 37 57 32 4a 35 64 47 56 62 58 } //1 "powershell -e ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCcxOTIuMTY4LjQ5Ljc2Jyw4MDgyKTsgPSAuR2V0U3RyZWFtKCk7W2J5dGVbX
		$a_01_1 = {53 68 65 6c 6c 20 53 74 72 2c 20 76 62 48 69 64 65 } //1 Shell Str, vbHide
		$a_01_2 = {73 54 69 6d 65 20 3d 20 44 61 74 65 44 69 66 66 28 22 73 22 2c 20 54 49 2c 20 54 4f 55 54 29 } //1 sTime = DateDiff("s", TI, TOUT)
		$a_01_3 = {53 6c 65 65 70 20 28 32 30 30 30 29 } //1 Sleep (2000)
		$a_01_4 = {41 75 74 6f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 46 6c 79 69 6e 67 4d 6f 6e 6b 65 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
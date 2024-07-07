
rule TrojanDownloader_O97M_Obfuse_ZB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ZB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 4d 79 46 75 5f 52 58 51 59 45 5f 32 30 32 31 30 33 32 39 5f } //1 Environ(MyFu_RXQYE_20210329_
		$a_01_1 = {2e 4e 61 6d 65 73 70 61 63 65 28 75 6e 5a 69 70 46 6f 6c 64 65 72 4e 61 6d 65 29 2e 43 6f 70 79 48 65 72 65 20 6f 62 72 71 78 6a 78 62 5a 69 52 58 51 59 45 70 49 74 5f 52 58 51 59 45 5f 32 30 32 31 30 33 32 39 5f 30 39 32 37 34 38 5f } //1 .Namespace(unZipFolderName).CopyHere obrqxjxbZiRXQYEpIt_RXQYE_20210329_092748_
		$a_01_2 = {66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 66 69 6c 65 50 61 74 68 29 } //1 fso.CreateTextFile(filePath)
		$a_01_3 = {52 65 73 75 6c 74 20 26 20 4d 69 64 28 43 65 6c 6c 52 65 66 2c 20 69 2c 20 31 29 } //1 Result & Mid(CellRef, i, 1)
		$a_01_4 = {47 65 74 54 65 6d 70 46 6f 6c 64 65 72 20 26 20 47 65 6e 65 72 61 74 65 52 61 5f 52 58 51 59 45 5f 32 30 32 31 30 33 32 39 5f 30 39 32 37 34 38 5f 72 71 78 6a 78 5f 6e 64 6f 6d 53 74 72 69 6e 67 } //1 GetTempFolder & GenerateRa_RXQYE_20210329_092748_rqxjx_ndomString
		$a_01_5 = {47 65 74 41 70 70 44 61 74 61 46 6f 6c 64 65 72 20 26 20 4d 79 46 75 5f 52 58 51 59 45 5f 32 30 32 31 30 33 32 39 5f 30 39 32 37 34 38 5f 72 71 78 6a 78 5f 6e 63 32 33 } //1 GetAppDataFolder & MyFu_RXQYE_20210329_092748_rqxjx_nc23
		$a_01_6 = {53 68 65 6c 6c 20 72 75 72 71 78 6a 78 6e 6e 52 58 51 59 45 65 5f 52 58 51 59 45 5f 32 30 32 31 30 33 32 39 5f 30 39 32 37 34 38 5f 72 71 78 6a 78 5f 72 2c 20 76 62 48 69 64 65 } //1 Shell rurqxjxnnRXQYEe_RXQYE_20210329_092748_rqxjx_r, vbHide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
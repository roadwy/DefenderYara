
rule TrojanDownloader_O97M_Gootkit_C_MSR{
	meta:
		description = "TrojanDownloader:O97M/Gootkit.C!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,19 00 19 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 42 61 73 65 20 3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //5 Attribute VB_Base = "1Normal.ThisDocument"
		$a_00_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //5 Sub AutoOpen()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //5 Private Sub Document_Open()
		$a_02_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 } //20
		$a_02_4 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [0-1a] 53 65 74 20 [0-10] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 [0-30] 49 66 20 [0-1a] 54 68 65 6e [0-1a] 45 6c 73 65 [0-10] 2e 52 75 6e 20 [0-1a] 45 6e 64 20 49 66 [0-05] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //15
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_02_3  & 1)*20+(#a_02_4  & 1)*15) >=25
 
}

rule TrojanDownloader_O97M_Obfuse_RH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 68 22 20 26 20 [0-20] 29 29 } //1
		$a_01_1 = {26 20 22 34 62 } //1 & "4b
		$a_01_2 = {26 20 22 35 } //1 & "5
		$a_01_3 = {26 20 22 37 } //1 & "7
		$a_01_4 = {33 33 33 34 33 33 } //1 333433
		$a_01_5 = {3d 20 49 73 4f 62 6a 65 63 74 28 22 22 29 } //1 = IsObject("")
		$a_01_6 = {26 20 22 22 20 26 } //1 & "" &
		$a_01_7 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
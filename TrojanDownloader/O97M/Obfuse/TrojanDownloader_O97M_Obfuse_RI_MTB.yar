
rule TrojanDownloader_O97M_Obfuse_RI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 56 61 6c 28 22 26 22 20 26 20 22 48 22 [0-04] 26 20 4d 69 64 24 28 [0-20] 2c } //1
		$a_01_1 = {26 20 22 34 62 } //1 & "4b
		$a_01_2 = {26 20 22 35 } //1 & "5
		$a_01_3 = {26 20 22 37 } //1 & "7
		$a_01_4 = {3d 20 49 73 45 6d 70 74 79 28 22 22 29 } //1 = IsEmpty("")
		$a_01_5 = {26 20 22 22 20 26 } //1 & "" &
		$a_01_6 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}

rule TrojanDownloader_O97M_Obfuse_RM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 73 45 6d 70 74 79 28 22 22 29 } //1 = IsEmpty("")
		$a_01_1 = {3d 20 49 73 4e 75 6d 65 72 69 63 28 22 22 29 } //1 = IsNumeric("")
		$a_03_2 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-15] 2c } //1
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-25] 2c 20 22 [0-20] 22 2c 20 22 22 29 20 26 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 [0-15] 22 2c 20 22 22 29 20 5f } //1
		$a_03_4 = {26 20 52 65 70 6c 61 63 65 28 [0-25] 2c 20 22 [0-25] 22 2c 20 22 22 29 20 26 20 22 22 20 26 20 22 22 20 26 } //1
		$a_01_5 = {26 20 22 34 } //1 & "4
		$a_01_6 = {26 20 22 33 } //1 & "3
		$a_01_7 = {26 20 22 32 } //1 & "2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
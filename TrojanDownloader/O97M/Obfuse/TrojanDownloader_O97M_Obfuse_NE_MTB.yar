
rule TrojanDownloader_O97M_Obfuse_NE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-35] 28 43 53 74 72 28 } //1
		$a_03_1 = {2b 20 22 77 [0-04] 69 [0-04] 6e [0-04] 6d 67 [0-04] 6d 74 73 [0-04] 3a 57 69 [0-04] 6e [0-08] 5f 50 72 [0-04] 6f 63 65 [0-04] 73 73 22 29 29 } //1
		$a_03_2 = {2e 43 72 65 61 74 65 28 [0-38] 2c } //1
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-35] 2c } //1
		$a_01_4 = {2c 20 4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 } //1 , MSForms, TextBox"
		$a_01_5 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
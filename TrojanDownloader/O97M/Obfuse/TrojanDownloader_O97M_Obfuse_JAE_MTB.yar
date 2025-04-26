
rule TrojanDownloader_O97M_Obfuse_JAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4d 69 64 28 [0-08] 2c 20 [0-08] 2c 20 31 29 } //1
		$a_01_1 = {53 70 6c 69 74 28 22 70 3a 5c 6a 76 61 71 62 6a 66 5c 66 6c 66 67 72 7a 33 32 5c 7a 66 75 67 6e 2e 72 6b 72 7c 50 3a 5c 68 66 72 65 66 5c 63 68 6f 79 76 70 5c 76 61 2e 70 62 7a 7c 50 3a 5c 68 66 72 65 66 5c 63 68 6f 79 76 70 5c 76 61 2e 75 67 7a 79 22 2c 20 22 7c 22 29 } //1 Split("p:\jvaqbjf\flfgrz32\zfugn.rkr|P:\hfref\choyvp\va.pbz|P:\hfref\choyvp\va.ugzy", "|")
		$a_03_2 = {52 65 70 6c 61 63 65 28 [0-08] 2c 20 [0-08] 2c 20 22 22 29 } //1
		$a_03_3 = {56 42 41 2e 43 68 72 28 [0-08] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
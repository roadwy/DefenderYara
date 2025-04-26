
rule TrojanDownloader_O97M_EncDoc_PAAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6d 64 75 6c 6f 31 22 70 } //1 vb_name="mdulo1"p
		$a_03_1 = {2f 64 6f 77 6e 6c 6f 61 64 2f 78 75 6e 6f 69 74 78 76 79 65 79 71 22 29 29 [0-3f] 2e 73 61 76 65 74 6f 66 69 6c 65 22 78 2e 76 62 73 22 2c 32 } //1
		$a_03_2 = {62 38 30 76 22 29 29 [0-3f] 2e 73 61 76 65 74 6f 66 69 6c 65 22 78 2e 76 62 73 22 2c 32 } //1
		$a_01_3 = {74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 22 78 2e 76 62 73 22 2c 30 2c 66 61 6c 73 65 65 6e 64 73 } //1 t.shell").run"x.vbs",0,falseends
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
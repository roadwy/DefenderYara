
rule TrojanDownloader_O97M_AgentTesla_RVL_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 74 70 3a 2f 2f 37 37 2e 38 33 2e 33 39 2e [0-03] 2f [0-0a] 2f [0-0a] 2e 70 73 31 22 [0-0a] 3d 22 63 3a 5c 74 65 6d 70 22 } //1
		$a_03_1 = {2e 72 75 6e 22 70 6f 77 65 72 73 68 65 6c 6c 2d 6e 6f 70 72 6f 66 69 6c 65 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 [0-0c] 2d 66 69 6c 65 22 22 22 26 [0-0a] 26 22 22 22 22 2c 30 2c } //1
		$a_01_2 = {73 75 62 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1 subdocument_open()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
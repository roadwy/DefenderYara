
rule TrojanDownloader_O97M_AgentTesla_RVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 22 68 74 74 70 3a 2f 2f 31 37 36 2e 36 35 2e 31 33 34 2e 37 39 2f 68 6f 73 74 69 6e 67 2f [0-0a] 2e 70 73 31 22 78 32 3d 22 63 3a 5c 5c 74 65 6d 70 5c 5c } //1
		$a_01_1 = {73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 subworkbook_open()
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
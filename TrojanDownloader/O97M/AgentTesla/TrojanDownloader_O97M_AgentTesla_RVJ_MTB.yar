
rule TrojanDownloader_O97M_AgentTesla_RVJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 22 70 6f 22 26 6c 2e 72 65 73 70 6f 6e 73 65 74 65 78 74 2c 76 62 68 69 64 65 65 6e 64 73 75 62 } //1 shell"po"&l.responsetext,vbhideendsub
		$a_01_1 = {2e 6f 70 65 6e 22 67 65 74 22 2c 22 68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 66 72 61 6e 6b 63 61 73 74 6c 65 32 2f 30 2f 6d 61 69 6e 2f 30 6a 22 } //1 .open"get","https://raw.githubusercontent.com/frankcastle2/0/main/0j"
		$a_01_2 = {65 6e 64 73 75 62 73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 endsubsubautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
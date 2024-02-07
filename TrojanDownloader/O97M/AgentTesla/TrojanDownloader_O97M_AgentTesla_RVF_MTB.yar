
rule TrojanDownloader_O97M_AgentTesla_RVF_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 5f 70 75 62 6c 69 63 20 2b 20 22 73 68 74 61 20 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 2e 77 77 77 2f 2f 3a 70 74 74 68 22 29 20 2b 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 68 6a 77 71 64 6f 71 69 77 6f 64 6d 61 22 } //01 00  P_public + "shta " + StrReverse(".www//:ptth") + "bitly.com/asdhjwqdoqiwodma"
		$a_01_1 = {50 5f 70 75 62 6c 69 63 20 3d 20 22 6d 22 } //01 00  P_public = "m"
		$a_01_2 = {6f 62 6a 32 2e 52 65 73 74 61 72 74 43 61 6c 6c 20 6f 62 6a 2e 6e 5f 6e 61 6d 65 } //01 00  obj2.RestartCall obj.n_name
		$a_01_3 = {53 75 62 20 61 75 74 6f 5f 63 6c 6f 73 65 28 29 } //00 00  Sub auto_close()
	condition:
		any of ($a_*)
 
}